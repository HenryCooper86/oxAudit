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
    let mut components: BTreeMap<ComponentId, Component> = BTreeMap::new();
    let mut component_ids = BTreeMap::new();
    let mut installation_ids = BTreeMap::new();
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
            dependency,
        )?;
        if crate::deps::osv::is_queryable_dependency(dependency) {
            component_ids.insert(
                (
                    dependency.ecosystem.clone(),
                    dependency.name.clone(),
                    dependency.version.clone(),
                ),
                component_id.clone(),
            );
        }
        if let Some(install_path) = &dependency.occurrence.install_path {
            let key = (
                normalize_path(&dependency.lockfile),
                dependency.ecosystem.clone(),
                dependency.name.clone(),
                normalize_path(install_path),
            );
            installation_ids
                .entry(key)
                .and_modify(|existing: &mut Option<ComponentId>| {
                    if existing.as_ref() != Some(&component_id) {
                        *existing = None; // Conflicting installation evidence cannot prove an edge.
                    }
                })
                .or_insert_with(|| Some(component_id.clone()));
        }
        let component = Component {
            depends_on: Vec::new(),
            license: dependency.license.clone(),
            id: component_id.clone(),
            name: dependency.name.clone(),
            version: (!dependency.version.is_empty()).then(|| dependency.version.clone()),
            supplier: None,
            ecosystem: Some(dependency.ecosystem.clone()),
            purl: crate::deps::osv::is_queryable_dependency(dependency).then(|| {
                format!(
                    "pkg/{}/{}@{}",
                    dependency.ecosystem.to_ascii_lowercase(),
                    dependency.name,
                    dependency.version
                )
            }),
            cpes: Vec::new(),
            aliases: Vec::new(),
            identities: vec![ComponentIdentity {
                method: IdentityMethod::DeclaredManifest,
                value: format!("{}@{}", dependency.name, dependency.version),
                confidence: 1.0,
                source_artifact_id: artifact.id.clone(),
            }],
        };
        if let Some(existing) = components.get_mut(&component_id) {
            for identity in component.identities {
                if !existing.identities.contains(&identity) {
                    existing.identities.push(identity);
                }
            }
        } else {
            components.insert(component_id, component);
        }
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
                    install_path: dependency.occurrence.install_path.clone(),
                    artifact_id: artifact.id.clone(),
                    ecosystem: dependency.ecosystem.clone(),
                    package_name: dependency.name.clone(),
                    declared_version: dependency.version.clone(),
                }),
            }],
        });
    }

    // Relationship edges from declaration chains (npm lockfiles v2/v3):
    // a chain is [entry point, ..., this package], so consecutive steps are
    // direct dependency edges. References are component ids — the same
    // strings CycloneDX uses as bom-refs. Only evidenced edges are recorded:
    // a component absent from this walk has no relationship evidence, never
    // "depends on nothing".
    {
        for dependency in dependencies {
            for path in &dependency.occurrence.paths {
                for pair in path.chain.windows(2) {
                    let (from, to) = (&pair[0], &pair[1]);
                    let from_id = installation_ids.get(&(
                        normalize_path(&dependency.lockfile),
                        dependency.ecosystem.clone(),
                        from.package_name.clone(),
                        normalize_path(&from.install_path),
                    ));
                    let to_id = installation_ids.get(&(
                        normalize_path(&dependency.lockfile),
                        dependency.ecosystem.clone(),
                        to.package_name.clone(),
                        normalize_path(&to.install_path),
                    ));
                    let (Some(Some(from_id)), Some(Some(to_id))) = (from_id, to_id) else {
                        continue;
                    };
                    let to_ref = to_id.as_str().to_string();
                    if let Some(component) = components.get_mut(from_id) {
                        if !component.depends_on.contains(&to_ref) {
                            component.depends_on.push(to_ref);
                        }
                    }
                }
            }
        }
        for component in components.values_mut() {
            component.depends_on.sort();
        }
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
                    install_path: vulnerability.occurrence.install_path.clone(),
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
    Ok((components.into_values().collect(), observations))
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
    dependency: &Dependency,
) -> Result<ComponentId, String> {
    let mut identity = format!("{}\0{}\0{}\0{}", run_id, ecosystem, name, version);
    if matches!(
        dependency.occurrence.source.as_deref(),
        Some("git" | "local")
    ) {
        // A declared non-registry version does not identify a registry release,
        // or prove equal source code across different lockfiles.
        identity.push_str(&format!(
            "\0{}\0{}",
            dependency.occurrence.source.as_deref().unwrap(),
            normalize_path(&dependency.lockfile)
        ));
    }
    ComponentId::parse(format!(
        "component_{:x}",
        Sha256::digest(identity.as_bytes())
    ))
    .map_err(|error| error.to_string())
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DependencyOccurrence, DependencyPath, DependencyStep};

    fn step(package_name: &str) -> DependencyStep {
        DependencyStep {
            name: package_name.to_string(),
            package_name: package_name.to_string(),
            install_path: format!("node_modules/{package_name}"),
            dependency_type: "prod".into(),
            declared: "^1.0.0".into(),
        }
    }

    fn dependency(name: &str, version: &str, chain: Vec<DependencyStep>) -> Dependency {
        Dependency {
            license: None,
            occurrence: DependencyOccurrence {
                status: "available".into(),
                install_path: Some(format!("node_modules/{name}")),
                local_workspace: false,
                paths: vec![DependencyPath {
                    workspace: String::new(),
                    entry_point: chain.first().map(|s| s.name.clone()).unwrap_or_default(),
                    chain,
                }],
                warnings: Vec::new(),
                ..Default::default()
            },
            ecosystem: "npm".into(),
            name: name.into(),
            version: version.into(),
            lockfile: "package-lock.json".into(),
        }
    }

    #[test]
    fn declaration_chains_become_cyclonedx_dependency_edges() {
        let run_id = RunId::parse("run-edge-test".to_string()).unwrap();
        let deps = vec![
            dependency("direct", "1.0.0", vec![step("direct")]),
            dependency("mid", "2.0.0", vec![step("direct"), step("mid")]),
            dependency(
                "leaf",
                "3.0.0",
                vec![step("direct"), step("mid"), step("leaf")],
            ),
            Dependency {
                license: None,
                occurrence: DependencyOccurrence::default(),
                ecosystem: "PyPI".into(),
                name: "flask".into(),
                version: "3.0.0".into(),
                lockfile: "requirements.txt".into(),
            },
        ];
        let artifact_for = |path: &str| Artifact {
            id: ArtifactId::new(),
            kind: oxaudit_domain::ArtifactKind::Lockfile,
            location: oxaudit_domain::ArtifactLocation {
                normalized_path: path.into(),
                canonical_path: None,
                parent_id: None,
            },
            size_bytes: 10,
            media_type: None,
            content_sha256: None,
        };
        let artifacts = BTreeMap::from([
            (
                "package-lock.json".to_string(),
                artifact_for("package-lock.json"),
            ),
            (
                "requirements.txt".to_string(),
                artifact_for("requirements.txt"),
            ),
        ]);
        let (components, _) = dependency_graph(&run_id, &deps, &[], &artifacts, None).unwrap();

        let find = |name: &str| {
            components
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("{name} component"))
        };
        assert_eq!(find("direct").depends_on, [find("mid").id.as_str()]);
        assert_eq!(find("mid").depends_on, [find("leaf").id.as_str()]);
        assert!(find("leaf").depends_on.is_empty());
        // No relationship evidence: no edges recorded, none claimed.
        assert!(find("flask").depends_on.is_empty());
    }
}
