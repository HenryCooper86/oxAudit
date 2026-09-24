//! Presentation- and storage-independent compliance readiness profiles.
//!
//! The engine reports evidence coverage, never legal compliance or certification.

use std::collections::BTreeSet;

use oxaudit_domain::RunKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const BUILTIN_PROFILES: &str = include_str!("../profiles/builtin.json");

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ComplianceError {
    #[error("the built-in compliance profile bundle is invalid")]
    InvalidBundle,
    #[error("unknown compliance profile: {0}")]
    UnknownProfile(String),
    #[error("invalid compliance profile: {0}")]
    InvalidProfile(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceProfile {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub domain: String,
    pub jurisdiction: String,
    pub source_label: String,
    pub source_url: String,
    pub copyright_notice: String,
    pub disclaimer: String,
    pub controls: Vec<ComplianceControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceControl {
    pub id: String,
    pub reference: String,
    pub title: String,
    pub objective: String,
    pub assurance: AssuranceKind,
    pub check: CheckSpec,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AssuranceKind {
    AutomatedEvidence,
    HumanAttestation,
    Mixed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CheckSpec {
    #[serde(default)]
    pub file_groups: Vec<Vec<String>>,
    #[serde(default)]
    pub run_kinds: Vec<RunKind>,
    #[serde(default)]
    pub manual: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSnapshot {
    pub root_label: String,
    pub files: Vec<EvidenceFile>,
    pub completed_runs: Vec<RunEvidence>,
    pub collection_limits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceFile {
    pub relative_path: String,
    pub size_bytes: u64,
    pub content_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunEvidence {
    pub run_id: String,
    pub kind: RunKind,
    pub target_label: String,
    pub completed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentMetadata {
    pub title: String,
    pub organization: String,
    pub assessor: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAssessment {
    pub schema_version: u32,
    pub id: String,
    pub profile_id: String,
    pub profile_name: String,
    pub profile_version: String,
    pub domain: String,
    pub source_label: String,
    pub source_url: String,
    pub disclaimer: String,
    pub metadata: AssessmentMetadata,
    pub target_label: String,
    pub created_at_ms: u64,
    pub controls: Vec<ControlAssessment>,
    pub summary: AssessmentSummary,
    pub collection_limits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ControlAssessment {
    pub control_id: String,
    pub reference: String,
    pub title: String,
    pub objective: String,
    pub assurance: AssuranceKind,
    pub automated_status: ReadinessStatus,
    pub rationale: String,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ReadinessStatus {
    Supported,
    Partial,
    Gap,
    ManualReview,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceReference {
    pub kind: String,
    pub label: String,
    pub locator: String,
    pub content_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentSummary {
    pub total: usize,
    pub supported: usize,
    pub partial: usize,
    pub gap: usize,
    pub manual_review: usize,
    pub not_applicable: usize,
    pub evidence_coverage_percent: u8,
}

pub fn builtin_profiles() -> Result<Vec<ComplianceProfile>, ComplianceError> {
    let profiles: Vec<ComplianceProfile> =
        serde_json::from_str(BUILTIN_PROFILES).map_err(|_| ComplianceError::InvalidBundle)?;
    validate_profiles(&profiles)?;
    Ok(profiles)
}

pub fn builtin_profile(id: &str) -> Result<ComplianceProfile, ComplianceError> {
    builtin_profiles()?
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| ComplianceError::UnknownProfile(id.to_owned()))
}

pub fn assess(
    profile: &ComplianceProfile,
    evidence: &EvidenceSnapshot,
    metadata: AssessmentMetadata,
    assessment_id: String,
    created_at_ms: u64,
) -> Result<ComplianceAssessment, ComplianceError> {
    validate_profile(profile)?;
    let controls = profile
        .controls
        .iter()
        .map(|control| evaluate_control(control, evidence))
        .collect::<Vec<_>>();
    let summary = summarize(&controls);
    Ok(ComplianceAssessment {
        schema_version: 1,
        id: assessment_id,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        profile_version: profile.version.clone(),
        domain: profile.domain.clone(),
        source_label: profile.source_label.clone(),
        source_url: profile.source_url.clone(),
        disclaimer: profile.disclaimer.clone(),
        metadata,
        target_label: evidence.root_label.clone(),
        created_at_ms,
        controls,
        summary,
        collection_limits: evidence.collection_limits.clone(),
    })
}

fn evaluate_control(control: &ComplianceControl, snapshot: &EvidenceSnapshot) -> ControlAssessment {
    if control.check.manual
        && control.check.file_groups.is_empty()
        && control.check.run_kinds.is_empty()
    {
        return control_result(
            control,
            ReadinessStatus::ManualReview,
            "A qualified reviewer must record this decision.",
            Vec::new(),
        );
    }

    let mut evidence = Vec::new();
    let mut matched_units = 0usize;
    let mut required_units = control.check.file_groups.len();
    for group in &control.check.file_groups {
        let matches = snapshot
            .files
            .iter()
            .filter(|file| {
                group
                    .iter()
                    .any(|pattern| wildcard_match(pattern, &file.relative_path))
            })
            .collect::<Vec<_>>();
        if !matches.is_empty() {
            matched_units += 1;
        }
        for file in matches.into_iter().take(5) {
            evidence.push(EvidenceReference {
                kind: "file".into(),
                label: file.relative_path.clone(),
                locator: file.relative_path.clone(),
                content_sha256: file.content_sha256.clone(),
            });
        }
    }
    if !control.check.run_kinds.is_empty() {
        required_units += 1;
        let runs = snapshot
            .completed_runs
            .iter()
            .filter(|run| control.check.run_kinds.contains(&run.kind))
            .collect::<Vec<_>>();
        if !runs.is_empty() {
            matched_units += 1;
        }
        for run in runs.into_iter().take(5) {
            evidence.push(EvidenceReference {
                kind: "run".into(),
                label: format!("{:?} scan", run.kind),
                locator: run.run_id.clone(),
                content_sha256: None,
            });
        }
    }
    evidence.sort_by(|left, right| left.locator.cmp(&right.locator));
    evidence.dedup_by(|left, right| left.kind == right.kind && left.locator == right.locator);

    let (status, rationale) = if required_units == 0 {
        (
            ReadinessStatus::ManualReview,
            "No automated evidence rule is defined; reviewer judgment is required.".into(),
        )
    } else if matched_units == required_units {
        let note = if control.check.manual {
            " Evidence is present, but final human review is still required."
        } else {
            ""
        };
        (
            ReadinessStatus::Supported,
            format!("Evidence matched all {required_units} expected evidence group(s).{note}"),
        )
    } else if matched_units > 0 {
        (
            ReadinessStatus::Partial,
            format!(
                "Evidence matched {matched_units} of {required_units} expected evidence group(s)."
            ),
        )
    } else {
        (
            ReadinessStatus::Gap,
            format!("No evidence matched the {required_units} expected evidence group(s)."),
        )
    };
    control_result(control, status, &rationale, evidence)
}

fn control_result(
    control: &ComplianceControl,
    status: ReadinessStatus,
    rationale: &str,
    evidence: Vec<EvidenceReference>,
) -> ControlAssessment {
    ControlAssessment {
        control_id: control.id.clone(),
        reference: control.reference.clone(),
        title: control.title.clone(),
        objective: control.objective.clone(),
        assurance: control.assurance,
        automated_status: status,
        rationale: rationale.into(),
        evidence,
    }
}

fn summarize(controls: &[ControlAssessment]) -> AssessmentSummary {
    let mut summary = AssessmentSummary {
        total: controls.len(),
        ..AssessmentSummary::default()
    };
    for control in controls {
        match control.automated_status {
            ReadinessStatus::Supported => summary.supported += 1,
            ReadinessStatus::Partial => summary.partial += 1,
            ReadinessStatus::Gap => summary.gap += 1,
            ReadinessStatus::ManualReview => summary.manual_review += 1,
            ReadinessStatus::NotApplicable => summary.not_applicable += 1,
        }
    }
    let assessable = summary
        .total
        .saturating_sub(summary.manual_review + summary.not_applicable);
    summary.evidence_coverage_percent = ((summary.supported * 100) + (summary.partial * 50))
        .checked_div(assessable)
        .unwrap_or_default()
        .min(100) as u8;
    summary
}

fn validate_profiles(profiles: &[ComplianceProfile]) -> Result<(), ComplianceError> {
    if profiles.is_empty() || profiles.len() > 32 {
        return Err(ComplianceError::InvalidBundle);
    }
    let mut ids = BTreeSet::new();
    for profile in profiles {
        validate_profile(profile)?;
        if !ids.insert(profile.id.as_str()) {
            return Err(ComplianceError::InvalidProfile(
                "duplicate profile id".into(),
            ));
        }
    }
    Ok(())
}

fn validate_profile(profile: &ComplianceProfile) -> Result<(), ComplianceError> {
    if profile.schema_version != 1 || profile.id.is_empty() || profile.name.is_empty() {
        return Err(ComplianceError::InvalidProfile(profile.id.clone()));
    }
    if !profile.source_url.starts_with("https://")
        || profile.disclaimer.len() < 40
        || profile.controls.is_empty()
        || profile.controls.len() > 100
    {
        return Err(ComplianceError::InvalidProfile(profile.id.clone()));
    }
    let mut ids = BTreeSet::new();
    for control in &profile.controls {
        if control.id.is_empty()
            || control.title.is_empty()
            || control.objective.is_empty()
            || !ids.insert(control.id.as_str())
        {
            return Err(ComplianceError::InvalidProfile(profile.id.clone()));
        }
        if control.check.file_groups.len() > 12
            || control
                .check
                .file_groups
                .iter()
                .flatten()
                .any(|pattern| pattern.len() > 160 || pattern.contains(".."))
        {
            return Err(ComplianceError::InvalidProfile(profile.id.clone()));
        }
    }
    Ok(())
}

fn wildcard_match(pattern: &str, path: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let path = path.replace('\\', "/").to_ascii_lowercase();
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return path == pattern || path.ends_with(&format!("/{pattern}"));
    }
    let mut cursor = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(found) = path[cursor..].find(part) else {
            return false;
        };
        if index == 0 && !pattern.starts_with('*') && found != 0 {
            return false;
        }
        cursor += found + part.len();
    }
    pattern.ends_with('*') || parts.last().is_some_and(|last| path.ends_with(last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_valid_and_reference_official_sources() {
        let profiles = builtin_profiles().unwrap();
        assert_eq!(profiles.len(), 10);
        assert!(profiles
            .iter()
            .all(|profile| profile.source_url.starts_with("https://")));
        assert!(profiles
            .iter()
            .all(|profile| profile.disclaimer.contains("not")));
    }

    #[test]
    fn assessment_distinguishes_evidence_from_attestation() {
        let profile = builtin_profile("gdpr").unwrap();
        let snapshot = EvidenceSnapshot {
            root_label: "/project".into(),
            files: vec![EvidenceFile {
                relative_path: "docs/privacy/data-inventory.md".into(),
                size_bytes: 10,
                content_sha256: Some("abc".into()),
            }],
            completed_runs: vec![],
            collection_limits: vec![],
        };
        let result = assess(
            &profile,
            &snapshot,
            AssessmentMetadata {
                title: "Readiness".into(),
                organization: "Acme".into(),
                assessor: "Sam".into(),
                scope: "Product".into(),
            },
            "assessment-1".into(),
            1,
        )
        .unwrap();
        assert!(result.summary.partial + result.summary.supported > 0);
        assert!(result.summary.manual_review > 0);
        assert_eq!(
            result.controls[0].evidence[0].content_sha256.as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn wildcard_matching_is_case_insensitive_and_bounded() {
        assert!(wildcard_match(
            "*privacy*inventory*",
            "Docs/Privacy/data-inventory.md"
        ));
        assert!(!wildcard_match("*hara*", "docs/privacy.md"));
    }
}
