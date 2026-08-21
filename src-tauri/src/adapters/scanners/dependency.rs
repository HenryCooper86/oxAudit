use std::collections::BTreeMap;

use oxaudit_application::ObservationRecord;
use oxaudit_domain::{
    AdvisoryMatchEvidence, Artifact, ArtifactId, Component, ComponentId, ComponentIdentity,
    Evidence, EvidenceId, EvidenceRecord, IdentityMethod, Observation, ObservationId,
    ObservationKind, PackageDeclarationEvidence, ProviderSnapshotId, RunId,
};
use sha2::{Digest, Sha256};

use crate::models::{Dependency, Vulnerability};

pub fn dependency_graph(
    run_id: &RunId,
    dependencies: &[Dependency],
    vulnerabilities: &[Vulnerability],
    artifacts: &BTreeMap<String, Artifact>,
    provider_snapshot_id: Option<&ProviderSnapshotId>,
) -> Result<(Vec<Component>, Vec<ObservationRecord>), String> {
    let mut components = Vec::with_capacity(dependencies.len());
    let mut component_ids = BTreeMap::new();
    let mut observations = Vec::new();
    for dependency in dependencies {
        let artifact = artifacts
            .get(&normalize_path(&dependency.lockfile))
            .ok_or_else(|| format!("lockfile artifact is missing for {}", dependency.lockfile))?;
        let component_id = component_id(
            run_id,
            &dependency.ecosystem,
            &dependency.name,
            &dependency.version,
        )?;
        component_ids.insert(
            (
                dependency.ecosystem.clone(),
                dependency.name.clone(),
                dependency.version.clone(),
            ),
            component_id.clone(),
        );
        components.push(Component {
            id: component_id,
            name: dependency.name.clone(),
            version: Some(dependency.version.clone()),
            supplier: None,
            ecosystem: Some(dependency.ecosystem.clone()),
            purl: Some(format!(
                "pkg/{}/{}@{}",
                dependency.ecosystem.to_ascii_lowercase(),
                dependency.name,
                dependency.version
            )),
            cpes: Vec::new(),
            aliases: Vec::new(),
            identities: vec![ComponentIdentity {
                method: IdentityMethod::DeclaredManifest,
                value: format!("{}@{}", dependency.name, dependency.version),
                confidence: 1.0,
                source_artifact_id: artifact.id.clone(),
            }],
        });
        let evidence_id = EvidenceId::new();
        observations.push(ObservationRecord {
            observation: Observation {
                id: ObservationId::new(),
                run_id: run_id.clone(),
                artifact_id: artifact.id.clone(),
                kind: ObservationKind::DependencyDeclaration,
                detector_id: "oxaudit.native.dependencies".into(),
                detector_version: env!("CARGO_PKG_VERSION").into(),
                rule_id: None,
                title: format!("{} {}", dependency.name, dependency.version),
                summary: format!("Declared {} dependency", dependency.ecosystem),
                evidence_ids: vec![evidence_id.clone()],
            },
            evidence: vec![EvidenceRecord {
                id: evidence_id,
                evidence: Evidence::PackageDeclaration(PackageDeclarationEvidence {
                    artifact_id: artifact.id.clone(),
                    ecosystem: dependency.ecosystem.clone(),
                    package_name: dependency.name.clone(),
                    declared_version: dependency.version.clone(),
                }),
            }],
        });
    }

    for vulnerability in vulnerabilities {
        let provider_snapshot_id = provider_snapshot_id.ok_or_else(|| {
            "OSV advisory evidence requires an immutable provider snapshot".to_string()
        })?;
        let key = (
            vulnerability.ecosystem.clone(),
            vulnerability.package_name.clone(),
            vulnerability.installed_version.clone(),
        );
        let Some(component_id) = component_ids.get(&key) else {
            return Err(format!(
                "advisory {} has no declared component",
                vulnerability.id
            ));
        };
        let artifact = artifacts
            .get(&normalize_path(&vulnerability.lockfile))
            .ok_or_else(|| {
                format!(
                    "lockfile artifact is missing for {}",
                    vulnerability.lockfile
                )
            })?;
        let evidence_id = EvidenceId::new();
        observations.push(ObservationRecord {
            observation: Observation {
                id: ObservationId::new(),
                run_id: run_id.clone(),
                artifact_id: artifact.id.clone(),
                kind: ObservationKind::AdvisoryMatch,
                detector_id: "oxaudit.provider.osv".into(),
                detector_version: "v1".into(),
                rule_id: Some(vulnerability.id.clone()),
                title: vulnerability.id.clone(),
                summary: vulnerability.summary.clone(),
                evidence_ids: vec![evidence_id.clone()],
            },
            evidence: vec![EvidenceRecord {
                id: evidence_id,
                evidence: Evidence::AdvisoryMatch(AdvisoryMatchEvidence {
                    component_id: component_id.clone(),
                    provider_snapshot_id: provider_snapshot_id.clone(),
                    advisory_id: vulnerability.id.clone(),
                    affected: true,
                    rationale: vulnerability
                        .affected_range
                        .clone()
                        .unwrap_or_else(|| "OSV matched the declared package version".into()),
                }),
            }],
        });
    }
    Ok((components, observations))
}

pub fn lockfile_artifact(run_id: &RunId, path: &std::path::Path) -> Result<Artifact, String> {
    let normalized = normalize_path(&path.to_string_lossy());
    let identity = format!(
        "artifact_{:x}",
        Sha256::digest(format!("{}\0{}", run_id, normalized).as_bytes())
    );
    Ok(Artifact {
        id: ArtifactId::parse(identity).map_err(|error| error.to_string())?,
        kind: oxaudit_domain::ArtifactKind::Lockfile,
        location: oxaudit_domain::ArtifactLocation {
            normalized_path: normalized,
            canonical_path: Some(path.to_string_lossy().into_owned()),
            parent_id: None,
        },
        size_bytes: path.metadata().map_err(|error| error.to_string())?.len(),
        media_type: Some("text/plain".into()),
        content_sha256: None,
    })
}

fn component_id(
    run_id: &RunId,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<ComponentId, String> {
    ComponentId::parse(format!(
        "component_{:x}",
        Sha256::digest(format!("{}\0{}\0{}\0{}", run_id, ecosystem, name, version).as_bytes())
    ))
    .map_err(|error| error.to_string())
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}
