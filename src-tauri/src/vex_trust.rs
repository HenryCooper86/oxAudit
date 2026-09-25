//! Trust grants and claim mapping for imported VEX/SARIF assertions.
//!
//! Imported claims are inert by design: `external-unverified`, immutable,
//! unable to touch findings or reviews. This module adds the explicit layer
//! on top — ADR 0003: a person grants trust to one document by its content
//! hash, and only then do that document's `not_affected` claims surface as
//! triage *suggestions*, matched by exact package identity. Suggestions are
//! report output; a review decision still needs a person.

use crate::adapters::reporting::import::ExternalClaim;
use crate::findings::repository::FindingsRepository;
use crate::models::Vulnerability;

/// A recorded grant of trust to one imported document, by content hash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrustGrant {
    pub content_sha256: String,
    pub granted_at_ms: u64,
    pub granted_by: String,
    pub note: String,
}

/// One imported claim set, as persisted by the importer.
#[derive(Debug, Clone)]
pub struct ClaimSet {
    pub run_id: String,
    pub content_sha256: String,
    pub format: String,
    pub claims: Vec<ExternalClaim>,
}

/// The identity forms a claim subject must carry to match a component:
/// exact purl or ecosystem-scoped coordinates. Case-insensitive, never
/// name-only — see ADR 0003.
fn subject_matches(subject: &str, vulnerability: &Vulnerability) -> bool {
    let candidates = [
        format!(
            "pkg/{}/{}@{}",
            vulnerability.ecosystem.to_ascii_lowercase(),
            vulnerability.package_name,
            vulnerability.installed_version
        ),
        format!(
            "{}:{}@{}",
            vulnerability.ecosystem.to_ascii_lowercase(),
            vulnerability.package_name,
            vulnerability.installed_version
        ),
    ];
    candidates
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(subject.trim()))
}

/// Whether the claim's vulnerability identifier names this advisory —
/// by id or one of its aliases.
fn vulnerability_named(claim: &ExternalClaim, vulnerability: &Vulnerability) -> bool {
    let Some(claimed) = claim.vulnerability_id.as_deref() else {
        return false;
    };
    let claimed = claimed.trim();
    claimed.eq_ignore_ascii_case(vulnerability.id.trim())
        || vulnerability
            .aliases
            .iter()
            .any(|alias| alias.trim().eq_ignore_ascii_case(claimed))
}

/// All local vulnerabilities one claim resolves to under the exact-identity
/// rule. Empty means unmapped.
pub fn claim_matches<'a>(
    claim: &ExternalClaim,
    vulnerabilities: &'a [Vulnerability],
) -> Vec<&'a Vulnerability> {
    vulnerabilities
        .iter()
        .filter(|vulnerability| {
            vulnerability_named(claim, vulnerability)
                && claim
                    .subject_ids
                    .iter()
                    .any(|subject| subject_matches(subject, vulnerability))
        })
        .collect()
}

/// Every imported claim set in the repository, newest first.
pub fn claim_sets(repository: &FindingsRepository) -> Result<Vec<ClaimSet>, String> {
    let runs = repository
        .canonical_list_runs(Some("external_evidence"), 100)
        .map_err(|error| format!("cannot list import runs: {error}"))?;
    let mut sets = Vec::new();
    for run in runs {
        let Ok(Some(projection)) = repository.canonical_load_projection(&run.id) else {
            continue;
        };
        let (Some(claims), Some(content_sha256)) = (
            projection
                .get("claims")
                .and_then(serde_json::Value::as_array),
            projection
                .get("contentSha256")
                .and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        let claims = claims
            .iter()
            .cloned()
            .filter_map(|claim| serde_json::from_value::<ExternalClaim>(claim).ok())
            .collect::<Vec<_>>();
        if claims.is_empty() {
            continue;
        }
        sets.push(ClaimSet {
            run_id: run.id.to_string(),
            content_sha256: content_sha256.to_string(),
            format: projection
                .get("format")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            claims,
        });
    }
    Ok(sets)
}

/// Grant trust to one imported claim set, captured by document content hash.
pub fn grant_trust(
    repository: &FindingsRepository,
    content_sha256: &str,
    granted_by: &str,
    note: &str,
) -> Result<TrustGrant, String> {
    let content_sha256 = content_sha256.trim().to_ascii_lowercase();
    if content_sha256.len() != 64 || !content_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "trust is granted per document content hash (64 hex characters); vex claims lists them"
                .into(),
        );
    }
    let sets = claim_sets(repository)?;
    if !sets
        .iter()
        .any(|set| set.content_sha256.eq_ignore_ascii_case(&content_sha256))
    {
        return Err(format!(
            "no imported claim set has content hash {content_sha256}; run `vex claims` to list imported documents"
        ));
    }
    let grant = TrustGrant {
        content_sha256,
        granted_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        granted_by: granted_by.trim().to_string(),
        note: note.trim().to_string(),
    };
    repository
        .save_trust_grant(&grant)
        .map_err(|error| format!("cannot record the trust grant: {error}"))?;
    Ok(grant)
}

/// Revoke a trust grant. Suggestions from that document stop appearing;
/// nothing else changes.
pub fn revoke_trust(repository: &FindingsRepository, content_sha256: &str) -> Result<(), String> {
    let content_sha256 = content_sha256.trim().to_ascii_lowercase();
    repository
        .delete_trust_grant(&content_sha256)
        .map_err(|error| format!("cannot revoke the trust grant: {error}"))
}

pub fn trust_grants(repository: &FindingsRepository) -> Result<Vec<TrustGrant>, String> {
    repository
        .trust_grants()
        .map_err(|error| format!("cannot list trust grants: {error}"))
}

/// One triage suggestion from a trusted claim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Suggestion {
    pub advisory_id: String,
    pub ecosystem: String,
    pub package_name: String,
    pub installed_version: String,
    pub status: String,
    pub justification: String,
    pub document_sha256: String,
    pub granted_by: String,
}

/// Everything `vex suggest` reports: suggestions plus the honest periphery —
/// claims consulted but unmapped, and documents not consulted because they
/// are untrusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuggestionReport {
    pub suggestions: Vec<Suggestion>,
    /// (document sha, claim record id, reason)
    pub unmapped: Vec<(String, String, String)>,
    /// (document sha, claim count) for untrusted documents not consulted.
    pub untrusted: Vec<(String, usize)>,
}

/// Map trusted claims against a set of local vulnerabilities.
///
/// Only `not_affected` claims produce suggestions — the status that would
/// otherwise ask a reviewer to dismiss. Other statuses are not triage input
/// for a dismissal and are deliberately not surfaced here.
pub fn suggest(
    sets: &[ClaimSet],
    grants: &[TrustGrant],
    vulnerabilities: &[Vulnerability],
) -> SuggestionReport {
    let mut report = SuggestionReport::default();
    for set in sets {
        let grant = grants
            .iter()
            .find(|grant| grant.content_sha256 == set.content_sha256);
        let Some(grant) = grant else {
            report
                .untrusted
                .push((set.content_sha256.clone(), set.claims.len()));
            continue;
        };
        for claim in &set.claims {
            let matches = claim_matches(claim, vulnerabilities);
            if matches.is_empty() {
                let reason = if claim.subject_ids.is_empty() {
                    "no subject identity".to_string()
                } else {
                    "no local vulnerability with this advisory and exact package identity"
                        .to_string()
                };
                report
                    .unmapped
                    .push((set.content_sha256.clone(), claim.record_id.clone(), reason));
                continue;
            }
            if claim.status != "not_affected" {
                continue;
            }
            for vulnerability in matches {
                report.suggestions.push(Suggestion {
                    advisory_id: vulnerability.id.clone(),
                    ecosystem: vulnerability.ecosystem.clone(),
                    package_name: vulnerability.package_name.clone(),
                    installed_version: vulnerability.installed_version.clone(),
                    status: claim.status.clone(),
                    justification: claim.summary.clone(),
                    document_sha256: set.content_sha256.clone(),
                    granted_by: grant.granted_by.clone(),
                });
            }
        }
    }
    report.suggestions.sort_by(|a, b| {
        a.package_name
            .cmp(&b.package_name)
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(vulnerability: &str, subjects: &[&str], status: &str) -> ExternalClaim {
        ExternalClaim {
            record_id: "record".into(),
            claim_kind: "vex-statement".into(),
            producer: "OpenVEX document".into(),
            rule_id: None,
            vulnerability_id: Some(vulnerability.into()),
            subject_ids: subjects.iter().map(|s| s.to_string()).collect(),
            status: status.into(),
            summary: "component not present".into(),
            location: None,
            trust: "external-unverified".into(),
        }
    }

    fn vulnerability(id: &str, aliases: &[&str], name: &str, version: &str) -> Vulnerability {
        Vulnerability {
            occurrence: Default::default(),
            affected_evidence: None,
            id: id.into(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: String::new(),
            details: String::new(),
            severity: None,
            cvss_score: None,
            epss: None,
            epss_percentile: None,
            known_exploited: false,
            ransomware: false,
            public_exploit: false,
            direct_usage: Default::default(),
            ecosystem: "npm".into(),
            package_name: name.into(),
            installed_version: version.into(),
            fixed_versions: Vec::new(),
            affected_range: None,
            references: Vec::new(),
            published: None,
            modified: None,
            lockfile: String::new(),
        }
    }

    #[test]
    fn claims_match_by_alias_and_exact_identity() {
        let vulnerabilities = vec![vulnerability(
            "GHSA-one",
            &["CVE-2024-1"],
            "left-pad",
            "1.3.0",
        )];
        // By alias, via purl subject.
        let matched = claim_matches(
            &claim("CVE-2024-1", &["pkg/npm/left-pad@1.3.0"], "not_affected"),
            &vulnerabilities,
        );
        assert_eq!(matched.len(), 1);
        // By id, via ecosystem coordinates, case-insensitive.
        let matched = claim_matches(
            &claim("ghsa-one", &["npm:left-pad@1.3.0"], "not_affected"),
            &vulnerabilities,
        );
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn version_or_name_only_subjects_do_not_match() {
        let vulnerabilities = vec![vulnerability("GHSA-one", &[], "left-pad", "1.3.0")];
        // Different version: a different component.
        assert!(claim_matches(
            &claim("GHSA-one", &["pkg/npm/left-pad@1.4.0"], "not_affected"),
            &vulnerabilities
        )
        .is_empty());
        // Name only: applies to nothing by decision.
        assert!(claim_matches(
            &claim("GHSA-one", &["pkg/npm/left-pad"], "not_affected"),
            &vulnerabilities
        )
        .is_empty());
        // Right identity, wrong advisory.
        assert!(claim_matches(
            &claim("GHSA-other", &["pkg/npm/left-pad@1.3.0"], "not_affected"),
            &vulnerabilities
        )
        .is_empty());
    }

    fn set(sha: &str, claims: Vec<ExternalClaim>) -> ClaimSet {
        ClaimSet {
            run_id: "run".into(),
            content_sha256: sha.into(),
            format: "openvex".into(),
            claims,
        }
    }

    fn grant(sha: &str) -> TrustGrant {
        TrustGrant {
            content_sha256: sha.into(),
            granted_at_ms: 1,
            granted_by: "auditor".into(),
            note: String::new(),
        }
    }

    #[test]
    fn suggestions_come_only_from_trusted_not_affected_claims() {
        let vulnerabilities = vec![vulnerability("CVE-2024-9", &[], "left-pad", "1.3.0")];
        let trusted = set(
            "a".repeat(64).as_str(),
            vec![
                claim("CVE-2024-9", &["pkg/npm/left-pad@1.3.0"], "not_affected"),
                claim("CVE-2024-9", &["pkg/npm/left-pad@1.3.0"], "affected"),
                claim("CVE-2024-8", &["pkg/npm/gone@1.0.0"], "not_affected"),
            ],
        );
        let untrusted = set(
            "b".repeat(64).as_str(),
            vec![claim(
                "CVE-2024-9",
                &["pkg/npm/left-pad@1.3.0"],
                "not_affected",
            )],
        );
        let report = suggest(
            &[trusted, untrusted],
            &[grant("a".repeat(64).as_str())],
            &vulnerabilities,
        );
        assert_eq!(report.suggestions.len(), 1);
        assert_eq!(report.suggestions[0].advisory_id, "CVE-2024-9");
        assert_eq!(report.suggestions[0].granted_by, "auditor");
        // affected-status match: consulted, but not a suggestion and not an
        // unmapped entry either.
        assert_eq!(report.unmapped.len(), 1);
        assert_eq!(
            report.unmapped[0].2,
            "no local vulnerability with this advisory and exact package identity"
        );
        // The untrusted document is summarized, not consulted.
        assert_eq!(report.untrusted, vec![("b".repeat(64), 1)]);
    }

    #[test]
    fn no_subject_claims_report_their_reason() {
        let vulnerabilities = vec![vulnerability("CVE-2024-9", &[], "left-pad", "1.3.0")];
        let trusted = set(
            "a".repeat(64).as_str(),
            vec![claim("CVE-2024-9", &[], "not_affected")],
        );
        let report = suggest(
            &[trusted],
            &[grant("a".repeat(64).as_str())],
            &vulnerabilities,
        );
        assert!(report.suggestions.is_empty());
        assert_eq!(report.unmapped[0].2, "no subject identity");
    }

    #[test]
    fn trust_and_suggestions_round_trip_through_a_real_import() {
        let directory = tempfile::tempdir().unwrap();
        let repository =
            FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();

        // Import an OpenVEX document through the real inspector and persist
        // its claims the way the import command does.
        let document = serde_json::json!({
            "@context": "https://openvex.dev/context",
            "@id": "https://example.com/vex/doc1",
            "statements": [{
                "vulnerability": { "name": "CVE-2099-5555" },
                "products": [{ "@id": "pkg/npm/left-pad@1.3.0" }],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path"
            }]
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        let analysis = crate::adapters::reporting::import::inspect(&bytes).unwrap();
        assert_eq!(analysis.external_claims.len(), 1);
        let mut run = oxaudit_domain::Run::queued(
            oxaudit_domain::RunKind::ExternalEvidence,
            "doc.openvex.json".to_string(),
            1,
        );
        let artifact = oxaudit_domain::Artifact {
            id: oxaudit_domain::ArtifactId::new(),
            kind: oxaudit_domain::ArtifactKind::Report,
            location: oxaudit_domain::ArtifactLocation {
                normalized_path: "doc.openvex.json".into(),
                canonical_path: None,
                parent_id: None,
            },
            size_bytes: bytes.len() as u64,
            media_type: None,
            content_sha256: Some(analysis.content_sha256.clone()),
        };
        let canonical = crate::adapters::persistence::CanonicalSqliteRepository::new(&repository);
        struct NoEvents;
        impl oxaudit_application::RunEventSink for NoEvents {
            fn publish(&self, _event: &oxaudit_application::EventEnvelope) -> Result<(), String> {
                Ok(())
            }
        }
        let events = NoEvents;
        let mut lifecycle = oxaudit_application::RunCoordinator::new(&canonical, &events)
            .begin(run.clone())
            .unwrap();
        for (state, at) in [
            (oxaudit_domain::RunState::Discovering, 2),
            (oxaudit_domain::RunState::Detecting, 3),
            (oxaudit_domain::RunState::Normalizing, 4),
            (oxaudit_domain::RunState::Assessing, 5),
            (oxaudit_domain::RunState::Persisting, 6),
        ] {
            lifecycle.transition(state, at).unwrap();
        }
        lifecycle.append_artifact(&artifact).unwrap();
        let completed = lifecycle.complete(7).unwrap();
        run = completed.run.clone();
        repository
            .canonical_save_projection(
                &run.id,
                "external-claims",
                1,
                &serde_json::json!({
                    "format": analysis.format,
                    "contentSha256": analysis.content_sha256,
                    "trustBoundary": "external-unverified",
                    "claims": analysis.external_claims,
                    "unmappedRecords": analysis.unmapped_records,
                }),
            )
            .unwrap();

        // The claim set is visible; trust requires the exact document hash.
        let sets = claim_sets(&repository).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].content_sha256, analysis.content_sha256);
        let wrong = "0".repeat(64);
        assert!(grant_trust(&repository, &wrong, "auditor", "").is_err());
        let grant = grant_trust(
            &repository,
            &sets[0].content_sha256,
            "auditor",
            "team review",
        )
        .unwrap();
        assert_eq!(trust_grants(&repository).unwrap(), vec![grant.clone()]);

        // Suggestions flow for the trusted document only.
        let vulnerabilities = vec![vulnerability(
            "GHSA-x",
            &["CVE-2099-5555"],
            "left-pad",
            "1.3.0",
        )];
        let report = suggest(&sets, std::slice::from_ref(&grant), &vulnerabilities);
        assert_eq!(report.suggestions.len(), 1);
        assert_eq!(report.suggestions[0].advisory_id, "GHSA-x");
        assert!(report.suggestions[0].justification.contains("not_affected"));

        // Revoking removes the document's influence and nothing else.
        revoke_trust(&repository, &sets[0].content_sha256).unwrap();
        let report = suggest(&sets, &[], &vulnerabilities);
        assert!(report.suggestions.is_empty());
        assert_eq!(report.untrusted.len(), 1);
    }
}
