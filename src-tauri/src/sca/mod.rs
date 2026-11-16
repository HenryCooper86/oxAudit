//! Software composition analysis over a dependency scan.
//!
//! The rules live in the `oxaudit-sca` crate. This module is the adapter
//! around them: it reads the committed component policy with the same
//! hardening as the other policy files, collects or reloads release facts,
//! turns a dependency scan result into the report's inputs, and rebuilds
//! reports from stored runs for the portfolio.
//!
//! One engine for every transport: the CLI calls these functions today, and
//! a desktop or server command would call the same ones.

pub mod releases;

use std::path::Path;

use oxaudit_sca::policy::{ComponentPolicy, COMPONENT_POLICY_FILE_NAME, COMPONENT_POLICY_PATH};
use oxaudit_sca::portfolio::ProjectEntry;
use oxaudit_sca::report::{ComponentAdvisory, ComponentInput};
use oxaudit_sca::{ReleaseInfo, ScaReport};

use crate::findings::repository::{FindingsRepository, ProviderSnapshotRecord};
use crate::models::{Dependency, DependencyScanResult};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
/// Provider identity of stored release-fact receipts.
pub const RELEASE_PROVIDER_ID: &str = "deps-dev-releases";
const RELEASE_RECEIPT_SCHEMA_VERSION: u64 = 1;

/// Where the component policy comes from.
#[derive(Clone, Copy, Debug)]
pub enum PolicySource<'a> {
    /// `<root>/.oxaudit/component-policy.json`, if the project has one.
    Project(&'a Path),
    /// A file named on the command line. Missing is an error.
    File(&'a Path),
}

/// The policy a report is assessed against.
#[derive(Debug, Default)]
pub struct LoadedPolicy {
    pub policy: ComponentPolicy,
    /// The path shown in reports, when a policy was read.
    pub source: Option<String>,
    pub notes: Vec<String>,
}

fn parse_policy(bytes: &[u8]) -> Result<ComponentPolicy, String> {
    let value = crate::findings::policy::parse_json_without_duplicates(bytes)
        .map_err(|_| "it is not valid JSON, or repeats a key".to_string())?;
    let policy = ComponentPolicy::from_value(value)?;
    if policy
        .reasons()
        .any(|reason| !crate::findings::policy::safe_required_text(reason))
    {
        return Err("a reason must not contain credentials, paths or URLs".into());
    }
    Ok(policy)
}

/// Load the component policy. A project without one gets the empty policy:
/// the report classifies everything and nothing is a violation. An invalid
/// policy is an error unless `ignore_invalid`, in which case the empty
/// policy is used and a note says so.
pub fn load_policy(source: PolicySource<'_>, ignore_invalid: bool) -> Result<LoadedPolicy, String> {
    let (read, shown_as) = match source {
        PolicySource::Project(root) => (
            crate::findings::policy::read_project_file(
                root,
                COMPONENT_POLICY_FILE_NAME,
                MAX_POLICY_BYTES,
            ),
            COMPONENT_POLICY_PATH.to_string(),
        ),
        PolicySource::File(path) => (
            crate::findings::policy::read_regular_file(path, MAX_POLICY_BYTES, true).map(Some),
            path.display().to_string(),
        ),
    };
    let parsed = match read {
        Ok(None) => return Ok(LoadedPolicy::default()),
        Ok(Some(bytes)) => parse_policy(&bytes),
        Err(error) => Err(error.message().to_string()),
    };
    match parsed {
        Ok(policy) => Ok(LoadedPolicy {
            policy,
            source: Some(shown_as),
            notes: Vec::new(),
        }),
        Err(reason) if ignore_invalid => Ok(LoadedPolicy {
            notes: vec![format!(
                "invalid {shown_as} was ignored ({reason}); no component rule is applied"
            )],
            ..Default::default()
        }),
        Err(reason) => Err(format!(
            "invalid {shown_as}: {reason}; fix or remove it (--ignore-invalid-policy reports \
             without it)"
        )),
    }
}

/// Whether the lockfile established this occurrence as a direct declaration.
/// A chain of one step is the project naming the package itself. Without
/// complete relationship evidence the answer is unknown, never "transitive".
fn direct(dependency: &Dependency) -> Option<bool> {
    let occurrence = &dependency.occurrence;
    if occurrence.paths.iter().any(|path| path.chain.len() == 1) {
        return Some(true);
    }
    (occurrence.status == "available" && !occurrence.paths.is_empty()).then_some(false)
}

/// The scan root's prefix removed from a lockfile path, for display.
fn relative_lockfile(lockfile: &str, root: &str) -> String {
    let normalized = lockfile.replace('\\', "/");
    let root = root.replace('\\', "/");
    normalized
        .strip_prefix(root.trim_end_matches('/'))
        .map(|rest| rest.trim_start_matches('/').to_string())
        .filter(|rest| !rest.is_empty())
        .unwrap_or(normalized)
}

/// One report input per inventory occurrence, with the advisories matched
/// to that occurrence.
pub fn inputs(result: &DependencyScanResult) -> Vec<ComponentInput> {
    let root = &result.summary.path;
    result
        .dependencies
        .iter()
        // Workspace members and path crates are the project's own code, not
        // third-party components: they are not classified or judged.
        .filter(|dependency| {
            !dependency.name.trim().is_empty() && !dependency.occurrence.local_workspace
        })
        .map(|dependency| ComponentInput {
            ecosystem: dependency.ecosystem.clone(),
            name: dependency.name.clone(),
            version: dependency.version.clone(),
            lockfile: relative_lockfile(&dependency.lockfile, root),
            license: dependency.license.clone(),
            direct: direct(dependency),
            registry: crate::deps::osv::is_queryable_dependency(dependency),
            advisories: result
                .vulnerabilities
                .iter()
                .filter(|vulnerability| {
                    vulnerability.ecosystem == dependency.ecosystem
                        && vulnerability.package_name == dependency.name
                        && vulnerability.installed_version == dependency.version
                        && vulnerability.lockfile == dependency.lockfile
                })
                .map(|vulnerability| ComponentAdvisory {
                    id: vulnerability.id.clone(),
                    severity: vulnerability.severity.clone(),
                    dismissed: vulnerability.review.is_some(),
                })
                .collect(),
        })
        .collect()
}

/// How release facts are obtained for a report.
pub enum ReleaseMode<'a> {
    /// Ask the index, and store the answer as a receipt.
    Fetch {
        http: &'a reqwest::Client,
        base: &'a str,
    },
    /// Reuse the newest stored receipt that covers the inventory.
    Cached,
    /// Do not collect them.
    Skip,
}

/// Release facts with how they were obtained.
#[derive(Debug, Default)]
pub struct ReleaseFacts {
    pub releases: Vec<ReleaseInfo>,
    /// `collected`, `partial`, `cached` or `notCollected`.
    pub status: &'static str,
    pub fetched_at_ms: Option<u64>,
    pub notes: Vec<String>,
}

fn not_collected(note: Option<String>) -> ReleaseFacts {
    ReleaseFacts {
        status: "notCollected",
        notes: note.into_iter().collect(),
        ..Default::default()
    }
}

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn receipt_hash(payload: &serde_json::Value) -> Result<String, String> {
    use sha2::Digest;
    let bytes = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
    Ok(hex::encode(sha2::Sha256::digest(bytes)))
}

/// Read a stored receipt back, refusing one that fails its integrity check
/// or is not in the expected shape.
fn load_receipt(snapshot: &ProviderSnapshotRecord) -> Result<Vec<ReleaseInfo>, String> {
    if receipt_hash(&snapshot.payload)? != snapshot.content_sha256 {
        return Err("stored release receipt failed its integrity check".into());
    }
    if snapshot
        .payload
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(RELEASE_RECEIPT_SCHEMA_VERSION)
    {
        return Err("stored release receipt has an unsupported schema".into());
    }
    serde_json::from_value(
        snapshot
            .payload
            .get("releases")
            .cloned()
            .ok_or("stored release receipt has no releases")?,
    )
    .map_err(|error| format!("stored release receipt is invalid: {error}"))
}

fn cached_releases(repository: &FindingsRepository, keys: &[String]) -> ReleaseFacts {
    let snapshot = match repository.provider_covering_snapshot(RELEASE_PROVIDER_ID, keys, None) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return not_collected(Some(
                "no stored release facts cover this inventory; operational rules were not \
                 evaluated. Run online once to collect them."
                    .into(),
            ))
        }
        Err(error) => {
            return not_collected(Some(format!(
                "stored release facts are unavailable: {error}"
            )))
        }
    };
    match load_receipt(&snapshot) {
        Ok(releases) => {
            let wanted: std::collections::BTreeSet<&String> = keys.iter().collect();
            ReleaseFacts {
                releases: releases
                    .into_iter()
                    .filter(|release| {
                        wanted.contains(&format!(
                            "{}\u{0}{}\u{0}{}",
                            release.ecosystem, release.name, release.version
                        ))
                    })
                    .collect(),
                status: "cached",
                fetched_at_ms: Some(snapshot.fetched_at_ms),
                notes: Vec::new(),
            }
        }
        Err(error) => not_collected(Some(format!(
            "{error}; operational rules were not evaluated"
        ))),
    }
}

/// Collect release facts for a scan's inventory.
pub async fn collect_releases(
    repository: &FindingsRepository,
    result: &DependencyScanResult,
    mode: ReleaseMode<'_>,
) -> ReleaseFacts {
    let keys = crate::deps::osv::query_keys(&result.dependencies);
    if keys.is_empty() {
        return not_collected(None);
    }
    match mode {
        ReleaseMode::Skip => not_collected(None),
        ReleaseMode::Cached => cached_releases(repository, &keys),
        ReleaseMode::Fetch { http, base } => {
            let fetched = releases::fetch(&result.dependencies, http, base).await;
            let fetched_at_ms = epoch_millis();
            let mut notes = fetched.notes;
            let complete =
                fetched.failed == 0 && fetched.skipped_no_source == 0 && notes.is_empty();
            let payload = serde_json::json!({
                "schemaVersion": RELEASE_RECEIPT_SCHEMA_VERSION,
                "queryKeys": keys,
                "releases": fetched.releases,
            });
            // The receipt lets an offline run and the portfolio reuse these
            // facts. Failing to store it loses that, not the report.
            let stored = receipt_hash(&payload).and_then(|content_sha256| {
                repository
                    .provider_save_snapshot(&ProviderSnapshotRecord {
                        id: format!("provider_{}", uuid::Uuid::new_v4()),
                        provider_id: RELEASE_PROVIDER_ID.into(),
                        fetched_at_ms,
                        content_sha256,
                        payload,
                    })
                    .map_err(|error| error.to_string())
            });
            if let Err(error) = stored {
                notes.push(format!(
                    "release facts could not be stored for reuse: {error}"
                ));
            }
            ReleaseFacts {
                releases: fetched.releases,
                status: if complete { "collected" } else { "partial" },
                fetched_at_ms: Some(fetched_at_ms),
                notes,
            }
        }
    }
}

/// Assemble the composition report for one dependency scan.
pub fn build_report(
    result: &DependencyScanResult,
    facts: &ReleaseFacts,
    loaded: &LoadedPolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> ScaReport {
    let mut report =
        oxaudit_sca::report::assess(inputs(result), &facts.releases, &loaded.policy, now);
    report.summary.run_id = result.summary.run_id.clone();
    report.summary.target = Some(result.summary.path.clone());
    report.summary.releases.status = facts.status.into();
    report.summary.releases.fetched_at_ms = facts.fetched_at_ms;
    report.summary.policy.loaded = loaded.source.is_some();
    report.summary.policy.source = loaded.source.clone();
    let mut notes = loaded.notes.clone();
    notes.extend(facts.notes.iter().cloned());
    if loaded.policy.uses_release_facts() && facts.status == "notCollected" {
        notes.push(
            "the policy has operational rules, but release facts were not collected: those \
             rules were not evaluated"
                .into(),
        );
    }
    notes.append(&mut report.summary.notes);
    report.summary.notes = notes;
    report
}

/// The policy applied to stored runs in a portfolio.
pub enum PortfolioPolicy<'a> {
    /// One policy for every project.
    Shared(&'a LoadedPolicy),
    /// Each project's own committed policy, read from its stored target
    /// directory when that still exists on this machine.
    PerProject,
}

/// Rebuild the composition report of each selected stored dependency run.
/// Stored runs are read-only: nothing is rewritten.
pub fn portfolio_entries(
    repository: &FindingsRepository,
    runs: &[oxaudit_domain::Run],
    policy: PortfolioPolicy<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<ProjectEntry>, String> {
    let mut entries = Vec::with_capacity(runs.len());
    for run in runs {
        let run_id = oxaudit_domain::RunId::parse(run.id.to_string())
            .map_err(|error| format!("run {}: {error}", run.id))?;
        let projection = repository
            .canonical_load_projection(&run_id)
            .map_err(|error| format!("run {}: {error}", run.id))?
            .ok_or_else(|| format!("run {} has no stored dependency result", run.id))?;
        let result: DependencyScanResult = serde_json::from_value(projection).map_err(|error| {
            format!(
                "run {}: stored dependency result is unreadable: {error}",
                run.id
            )
        })?;
        let keys = crate::deps::osv::query_keys(&result.dependencies);
        let facts = if keys.is_empty() {
            not_collected(None)
        } else {
            cached_releases(repository, &keys)
        };
        let own;
        let loaded = match &policy {
            PortfolioPolicy::Shared(loaded) => *loaded,
            PortfolioPolicy::PerProject => {
                let root = Path::new(&result.summary.path);
                own = if root.is_dir() {
                    // A project whose policy is broken still appears, with
                    // the problem stated on its row.
                    load_policy(PolicySource::Project(root), true)?
                } else {
                    LoadedPolicy {
                        notes: vec![
                            "the project directory is not on this machine; no component policy \
                             was applied"
                                .into(),
                        ],
                        ..Default::default()
                    }
                };
                &own
            }
        };
        let mut report = build_report(&result, &facts, loaded, now);
        // The portfolio is about policy state, not about whether this
        // machine has a release receipt for every project.
        report.summary.run_id = Some(run.id.to_string());
        entries.push(ProjectEntry {
            target: result.summary.path.clone(),
            run_id: run.id.to_string(),
            scanned_at_ms: Some(run.updated_at_ms),
            report,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests;
