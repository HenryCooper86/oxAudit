//! Versioned dependency baselines compare advisory/package/version identities.
//! Lockfile locations remain provenance, so moving or duplicating an existing
//! package does not create a new advisory identity.
use crate::models::{Dependency, DependencyScanResult, Vulnerability};
use serde::Deserialize;
use std::{collections::BTreeSet, path::Path};
type Identity = (String, String, String, String);
pub struct Baseline {
    identities: BTreeSet<Identity>,
}
impl Baseline {
    pub fn contains(&self, vulnerability: &Vulnerability) -> bool {
        self.identities.contains(&(
            vulnerability.ecosystem.clone(),
            vulnerability.package_name.clone(),
            vulnerability.installed_version.clone(),
            vulnerability.id.clone(),
        ))
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    schema_version: u64,
    kind: String,
    summary: Summary,
    dependencies: Vec<Dependency>,
    vulnerabilities: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    advisory_coverage: String,
    packages_found: usize,
    packages_queried: usize,
    vulnerabilities_found: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    id: String,
    ecosystem: String,
    package_name: String,
    installed_version: String,
    lockfile: String,
}

pub fn load(path: &Path) -> Result<Baseline, String> {
    use std::io::Read;
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read dependency baseline: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("dependency baseline exceeds 64 MiB".into());
    }
    let report: Envelope =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid dependency baseline: {e}"))?;
    if report.schema_version != 1
        || report.kind != "dependencies"
        || report.summary.advisory_coverage != "complete"
    {
        return Err("dependency baseline must be schemaVersion 1, kind dependencies, with complete advisory coverage".into());
    }
    if report.summary.packages_found != report.dependencies.len()
        || report.summary.vulnerabilities_found != report.vulnerabilities.len()
    {
        return Err(
            "incomplete dependency baseline: inventory or vulnerability counts disagree".into(),
        );
    }
    let queries = crate::deps::osv::query_keys(&report.dependencies)
        .into_iter()
        .collect::<BTreeSet<_>>();
    if report.summary.packages_queried != queries.len() {
        return Err("incomplete dependency baseline: query counts disagree".into());
    }
    let mut inventory = BTreeSet::new();
    for dependency in report.dependencies {
        let local_go = dependency.ecosystem == "Go"
            && dependency.occurrence.local_workspace
            && dependency.occurrence.source.as_deref() == Some("local");
        if [
            &dependency.ecosystem,
            &dependency.name,
            &dependency.lockfile,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || (dependency.version.trim().is_empty()
                && !local_go
                && !(dependency.ecosystem == "npm"
                    && dependency.occurrence.local_workspace
                    && dependency
                        .occurrence
                        .install_path
                        .as_deref()
                        .is_some_and(|path| {
                            !path.is_empty()
                                && !path.starts_with('/')
                                && !path.contains("node_modules/")
                                && !path.contains('\\')
                                && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
                        })))
        {
            return Err("invalid dependency baseline: missing inventory identity".into());
        }
        inventory.insert((
            dependency.ecosystem,
            dependency.name,
            dependency.version,
            dependency.lockfile,
        ));
    }
    let mut identities = BTreeSet::new();
    for entry in report.vulnerabilities {
        if [
            &entry.id,
            &entry.ecosystem,
            &entry.package_name,
            &entry.installed_version,
            &entry.lockfile,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || !inventory.contains(&(
                entry.ecosystem.clone(),
                entry.package_name.clone(),
                entry.installed_version.clone(),
                entry.lockfile,
            ))
        {
            return Err(
                "invalid dependency baseline: advisory identity is missing or outside inventory"
                    .into(),
            );
        }
        identities.insert((
            entry.ecosystem,
            entry.package_name,
            entry.installed_version,
            entry.id,
        ));
    }
    Ok(Baseline { identities })
}
pub fn report(result: &DependencyScanResult) -> serde_json::Value {
    serde_json::json!({"schemaVersion":1,"kind":"dependencies","summary":result.summary,"dependencies":result.dependencies,"vulnerabilities":result.vulnerabilities})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::json!({"schemaVersion":1,"kind":"dependencies","summary":{"advisoryCoverage":"complete","packagesFound":1,"packagesQueried":1,"vulnerabilitiesFound":1},"dependencies":[{"ecosystem":"npm","name":"example","version":"1.0.0","lockfile":"a/package-lock.json"}],"vulnerabilities":[{"id":"GHSA-example","ecosystem":"npm","packageName":"example","installedVersion":"1.0.0","lockfile":"a/package-lock.json"}]})
    }
    fn read(value: &serde_json::Value) -> Result<Baseline, String> {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(value).unwrap()).unwrap();
        load(file.path())
    }
    #[test]
    fn versionless_linked_workspace_is_accepted_but_missing_registry_version_is_not() {
        let directory = tempfile::tempdir().unwrap();
        let lockfile = directory.path().join("package-lock.json");
        std::fs::write(
            &lockfile,
            r#"{"lockfileVersion":3,"packages":{
          "":{"workspaces":["packages/*"]},"packages/worker":{"name":"@qa/worker"},
          "node_modules/@qa/worker":{"link":true,"resolved":"packages/worker"}}}"#,
        )
        .unwrap();
        let deps = crate::deps::lockfiles::parse_lockfile(&lockfile, "npm").unwrap();
        let mut value = serde_json::json!({"schemaVersion":1,"kind":"dependencies",
          "summary":{"advisoryCoverage":"complete","packagesFound":1,"packagesQueried":0,"vulnerabilitiesFound":0},"dependencies":deps,"vulnerabilities":[]});
        assert!(read(&value).is_ok());
        value["dependencies"][0]["occurrence"]["localWorkspace"] = false.into();
        assert!(read(&value).is_err());
    }
    #[test]
    fn unnamed_versionless_workspace_baselines_keep_inferred_identity() {
        for version in [2, 3] {
            let directory = tempfile::tempdir().unwrap();
            let lockfile = directory.path().join("package-lock.json");
            std::fs::write(&lockfile,serde_json::to_vec(&serde_json::json!({"lockfileVersion":version,"packages":{
                "":{"workspaces":["packages/*"]},"node_modules/a":{"link":true,"resolved":"packages/a"},"packages/a":{}
            }})).unwrap()).unwrap();
            let deps = crate::deps::lockfiles::parse_lockfile(&lockfile, "npm").unwrap();
            assert_eq!(deps[0].name, "a");
            assert!(deps[0].version.is_empty());
            assert!(crate::deps::osv::query_keys(&deps).is_empty());
            let value = serde_json::json!({"schemaVersion":1,"kind":"dependencies","summary":{"advisoryCoverage":"complete","packagesFound":1,"packagesQueried":0,"vulnerabilitiesFound":0},"dependencies":deps,"vulnerabilities":[]});
            assert!(read(&value).is_ok());
        }
    }

    #[test]
    fn local_go_replacement_baselines_round_trip_without_inventing_versions() {
        let root = tempfile::tempdir().unwrap();
        let lockfile = root.path().join("go.mod");
        std::fs::write(
            &lockfile,
            "module example.com/app\nrequire example.com/a v1.0.0\nreplace example.com/a => .\n",
        )
        .unwrap();
        let deps = crate::deps::lockfiles::parse_lockfile(&lockfile, "gomod").unwrap();
        let mut value = serde_json::json!({"schemaVersion":1,"kind":"dependencies",
          "summary":{"advisoryCoverage":"complete","packagesFound":1,"packagesQueried":0,"vulnerabilitiesFound":0},"dependencies":deps,"vulnerabilities":[]});
        assert!(read(&value).is_ok());
        value["dependencies"][0]["occurrence"]["source"] = "registry".into();
        assert!(read(&value).is_err());
    }
    #[test]
    fn complete_dependency_baseline_is_accepted() {
        assert!(read(&fixture()).is_ok());
    }
    #[test]
    fn baselines_reject_wrong_kind_missing_identity_and_incomplete_counts() {
        for pointer in [
            "/kind",
            "/schemaVersion",
            "/summary/advisoryCoverage",
            "/summary/packagesFound",
            "/summary/packagesQueried",
            "/summary/vulnerabilitiesFound",
            "/vulnerabilities/0/id",
            "/vulnerabilities/0/packageName",
            "/vulnerabilities/0/installedVersion",
            "/dependencies/0/version",
        ] {
            let mut value = fixture();
            *value.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
            assert!(read(&value).is_err(), "{pointer}");
        }
        let mut value = fixture();
        value["kind"] = "source".into();
        assert!(read(&value).is_err());
        let mut value = fixture();
        value["summary"]["advisoryCoverage"] = "unknown".into();
        assert!(read(&value).is_err());
        let mut value = fixture();
        value["summary"]["vulnerabilitiesFound"] = 0.into();
        assert!(read(&value).is_err());
    }
}
