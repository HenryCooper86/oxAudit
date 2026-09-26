use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use oxaudit_compliance::{
    AssessmentMetadata, ComplianceAssessment, ComplianceProfile, EvidenceFile, EvidenceSnapshot,
    ReadinessStatus, RunEvidence,
};
use oxaudit_domain::RunState;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::findings::service::FindingsState;

const MAX_EVIDENCE_FILES: usize = 10_000;
const MAX_HASH_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_HASH_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_WALK_DEPTH: usize = 8;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunComplianceRequest {
    pub target_path: String,
    pub profile_ids: Vec<String>,
    pub title: String,
    pub organization: String,
    pub assessor: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReview {
    pub id: String,
    pub assessment_id: String,
    pub control_id: String,
    pub status: ReadinessStatus,
    pub note: String,
    pub author: String,
    pub reviewed_at_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveComplianceReviewRequest {
    pub assessment_id: String,
    pub control_id: String,
    pub status: ReadinessStatus,
    pub note: String,
    pub author: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAssessmentView {
    pub assessment: ComplianceAssessment,
    pub reviews: Vec<ComplianceReview>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceReportFormat {
    Json,
    Csv,
    Markdown,
    Html,
    Pdf,
}

impl ComplianceReportFormat {
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Markdown => "md",
            Self::Html => "html",
            Self::Pdf => "pdf",
        }
    }

    pub fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Csv => "text/csv",
            Self::Markdown => "text/markdown",
            Self::Html => "text/html",
            Self::Pdf => "application/pdf",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportMetadata {
    pub title: String,
    pub organization: String,
    pub assessor: String,
    pub classification: String,
    pub executive_summary: String,
    pub include_evidence: bool,
    pub include_reviews: bool,
    pub include_references: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportRequest {
    pub assessment_id: String,
    pub format: ComplianceReportFormat,
    pub metadata: ComplianceReportMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteComplianceReportRequest {
    pub assessment_id: String,
    pub format: ComplianceReportFormat,
    pub metadata: ComplianceReportMetadata,
    pub output_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportPreview {
    pub format: ComplianceReportFormat,
    pub media_type: String,
    pub suggested_file_name: String,
    pub content: String,
    pub truncated: bool,
    pub bytes: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportReceipt {
    pub id: String,
    pub assessment_id: String,
    pub format: ComplianceReportFormat,
    pub output_path: String,
    pub content_sha256: String,
    pub created_at_ms: u64,
    pub metadata: ComplianceReportMetadata,
}

#[tauri::command]
pub fn list_compliance_profiles() -> Result<Vec<ComplianceProfile>, String> {
    oxaudit_compliance::builtin_profiles().map_err(|error| error.to_string())
}

#[tauri::command]
pub fn run_compliance_assessment(
    findings: State<'_, FindingsState>,
    request: RunComplianceRequest,
) -> Result<Vec<ComplianceAssessment>, String> {
    run_compliance_assessment_inner(&findings, request)
}

pub(crate) fn run_compliance_assessment_inner(
    findings: &FindingsState,
    request: RunComplianceRequest,
) -> Result<Vec<ComplianceAssessment>, String> {
    validate_run_request(&request)?;
    let service = findings.service().map_err(|error| error.to_string())?;
    let root = canonical_directory(&request.target_path)?;
    let evidence = collect_evidence(&root, service.repository())?;
    let now = now_ms();
    let metadata = AssessmentMetadata {
        title: bounded(&request.title, 160, "Assessment title")?,
        organization: bounded(&request.organization, 160, "Organization")?,
        assessor: bounded(&request.assessor, 160, "Assessor")?,
        scope: bounded(&request.scope, 2_000, "Scope")?,
    };
    let mut assessments = Vec::with_capacity(request.profile_ids.len());
    for profile_id in &request.profile_ids {
        let profile =
            oxaudit_compliance::builtin_profile(profile_id).map_err(|error| error.to_string())?;
        let assessment = oxaudit_compliance::assess(
            &profile,
            &evidence,
            metadata.clone(),
            format!("assessment_{}", Uuid::new_v4()),
            now,
        )
        .map_err(|error| error.to_string())?;
        service
            .repository()
            .compliance_save_assessment(&assessment)
            .map_err(|error| error.to_string())?;
        assessments.push(assessment);
    }
    Ok(assessments)
}

#[tauri::command]
pub fn list_compliance_assessments(
    findings: State<'_, FindingsState>,
    limit: Option<usize>,
) -> Result<Vec<ComplianceAssessment>, String> {
    list_compliance_assessments_inner(&findings, limit)
}

pub(crate) fn list_compliance_assessments_inner(
    findings: &FindingsState,
    limit: Option<usize>,
) -> Result<Vec<ComplianceAssessment>, String> {
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .compliance_list_assessments(limit.unwrap_or(50))
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn load_compliance_assessment(
    findings: State<'_, FindingsState>,
    assessment_id: String,
) -> Result<ComplianceAssessmentView, String> {
    load_compliance_assessment_inner(&findings, assessment_id)
}

pub(crate) fn load_compliance_assessment_inner(
    findings: &FindingsState,
    assessment_id: String,
) -> Result<ComplianceAssessmentView, String> {
    let repository = findings
        .service()
        .map_err(|error| error.to_string())?
        .repository();
    Ok(ComplianceAssessmentView {
        assessment: repository
            .compliance_load_assessment(&assessment_id)
            .map_err(|error| error.to_string())?,
        reviews: repository
            .compliance_list_reviews(&assessment_id)
            .map_err(|error| error.to_string())?,
    })
}

#[tauri::command]
pub fn save_compliance_review(
    findings: State<'_, FindingsState>,
    request: SaveComplianceReviewRequest,
) -> Result<ComplianceReview, String> {
    save_compliance_review_inner(&findings, request)
}

pub(crate) fn save_compliance_review_inner(
    findings: &FindingsState,
    request: SaveComplianceReviewRequest,
) -> Result<ComplianceReview, String> {
    let repository = findings
        .service()
        .map_err(|error| error.to_string())?
        .repository();
    let assessment = repository
        .compliance_load_assessment(&request.assessment_id)
        .map_err(|error| error.to_string())?;
    if !assessment
        .controls
        .iter()
        .any(|control| control.control_id == request.control_id)
    {
        return Err("the control does not belong to this assessment".into());
    }
    let note = bounded(&request.note, 4_000, "Review note")?;
    let author = bounded(&request.author, 160, "Reviewer")?;
    if note.trim().len() < 4 || author.trim().len() < 2 {
        return Err("reviewer and a meaningful review note are required".into());
    }
    let review = ComplianceReview {
        id: format!("review_{}", Uuid::new_v4()),
        assessment_id: request.assessment_id,
        control_id: request.control_id,
        status: request.status,
        note,
        author,
        reviewed_at_ms: now_ms(),
    };
    repository
        .compliance_save_review(&review)
        .map_err(|error| error.to_string())?;
    Ok(review)
}

#[tauri::command]
pub fn preview_compliance_report(
    findings: State<'_, FindingsState>,
    request: ComplianceReportRequest,
) -> Result<ComplianceReportPreview, String> {
    preview_compliance_report_inner(&findings, request)
}

pub(crate) fn preview_compliance_report_inner(
    findings: &FindingsState,
    request: ComplianceReportRequest,
) -> Result<ComplianceReportPreview, String> {
    let generated = generate_report(
        findings,
        &request.assessment_id,
        request.format,
        &request.metadata,
    )?;
    const PREVIEW_LIMIT: usize = 1024 * 1024;
    let truncated = generated.bytes.len() > PREVIEW_LIMIT;
    let content = if request.format == ComplianceReportFormat::Pdf {
        format!(
            "Professional PDF ready - {} bytes - {}",
            generated.bytes.len(),
            generated.preview_summary
        )
    } else {
        String::from_utf8_lossy(&generated.bytes[..generated.bytes.len().min(PREVIEW_LIMIT)])
            .into_owned()
    };
    Ok(ComplianceReportPreview {
        format: request.format,
        media_type: request.format.media_type().into(),
        suggested_file_name: format!(
            "{}-compliance-report.{}",
            safe_slug(&generated.profile_name),
            request.format.suffix()
        ),
        content,
        truncated,
        bytes: generated.bytes.len(),
        warnings: generated.warnings,
    })
}

#[tauri::command]
pub fn write_compliance_report(
    findings: State<'_, FindingsState>,
    request: WriteComplianceReportRequest,
) -> Result<ComplianceReportReceipt, String> {
    write_compliance_report_inner(&findings, request)
}

pub(crate) fn write_compliance_report_inner(
    findings: &FindingsState,
    request: WriteComplianceReportRequest,
) -> Result<ComplianceReportReceipt, String> {
    let generated = generate_report(
        findings,
        &request.assessment_id,
        request.format,
        &request.metadata,
    )?;
    let destination = PathBuf::from(&request.output_path);
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty() && parent.is_dir())
        .ok_or_else(|| "report destination directory does not exist".to_string())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("could not create report file: {error}"))?;
    temporary
        .write_all(&generated.bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("could not write report: {error}"))?;
    temporary
        .persist(&destination)
        .map_err(|error| format!("could not finalize report: {}", error.error))?;
    let receipt = ComplianceReportReceipt {
        id: format!("report_{}", Uuid::new_v4()),
        assessment_id: request.assessment_id,
        format: request.format,
        output_path: destination.to_string_lossy().into_owned(),
        content_sha256: format!("{:x}", Sha256::digest(&generated.bytes)),
        created_at_ms: now_ms(),
        metadata: request.metadata,
    };
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .compliance_save_report(&receipt)
        .map_err(|error| error.to_string())?;
    Ok(receipt)
}

struct GeneratedComplianceReport {
    bytes: Vec<u8>,
    warnings: Vec<String>,
    profile_name: String,
    preview_summary: String,
}

fn generate_report(
    findings: &FindingsState,
    assessment_id: &str,
    format: ComplianceReportFormat,
    metadata: &ComplianceReportMetadata,
) -> Result<GeneratedComplianceReport, String> {
    validate_report_metadata(metadata)?;
    let repository = findings
        .service()
        .map_err(|error| error.to_string())?
        .repository();
    let assessment = repository
        .compliance_load_assessment(assessment_id)
        .map_err(|error| error.to_string())?;
    let reviews = repository
        .compliance_list_reviews(assessment_id)
        .map_err(|error| error.to_string())?;
    let report = crate::adapters::reporting::compliance::ReportDocument {
        assessment,
        reviews,
        metadata: metadata.clone(),
        generated_at_ms: now_ms(),
    };
    let generated = crate::adapters::reporting::compliance::generate(&report, format)?;
    Ok(GeneratedComplianceReport {
        preview_summary: format!(
            "{} controls, {} reviewer decisions",
            report.assessment.controls.len(),
            report.reviews.len()
        ),
        profile_name: report.assessment.profile_name,
        bytes: generated.bytes,
        warnings: generated.warnings,
    })
}

fn validate_run_request(request: &RunComplianceRequest) -> Result<(), String> {
    if request.profile_ids.is_empty() || request.profile_ids.len() > 8 {
        return Err("select between one and eight compliance profiles".into());
    }
    let unique = request.profile_ids.iter().collect::<BTreeSet<_>>();
    if unique.len() != request.profile_ids.len() {
        return Err("duplicate compliance profiles are not allowed".into());
    }
    Ok(())
}

fn validate_report_metadata(metadata: &ComplianceReportMetadata) -> Result<(), String> {
    bounded(&metadata.title, 160, "Report title")?;
    bounded(&metadata.organization, 160, "Organization")?;
    bounded(&metadata.assessor, 160, "Assessor")?;
    bounded(&metadata.classification, 80, "Classification")?;
    bounded(&metadata.executive_summary, 8_000, "Executive summary")?;
    Ok(())
}

fn bounded(value: &str, max: usize, label: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max {
        Err(format!(
            "{label} must contain between 1 and {max} characters"
        ))
    } else {
        Ok(value.into())
    }
}

fn canonical_directory(path: &str) -> Result<PathBuf, String> {
    let root = PathBuf::from(path)
        .canonicalize()
        .map_err(|_| "the selected compliance target is unavailable".to_string())?;
    if !root.is_dir() {
        return Err("the compliance target must be a project directory".into());
    }
    Ok(root)
}

fn collect_evidence(
    root: &Path,
    repository: &crate::findings::repository::FindingsRepository,
) -> Result<EvidenceSnapshot, String> {
    let mut files = Vec::new();
    let mut hash_budget = 0u64;
    let mut truncated = false;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_entry(|entry| !ignored_entry(root, entry.path()))
    {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(canonical_path) = entry.path().canonicalize() else {
            continue;
        };
        if !canonical_path.starts_with(root) {
            continue;
        }
        if files.len() == MAX_EVIDENCE_FILES {
            truncated = true;
            break;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let size_bytes = metadata.len();
        let relative_path = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        let content_sha256 = if size_bytes <= MAX_HASH_FILE_BYTES
            && hash_budget.saturating_add(size_bytes) <= MAX_HASH_TOTAL_BYTES
            && likely_evidence_file(entry.path())
        {
            hash_budget += size_bytes;
            hash_file(root, &canonical_path).ok()
        } else {
            None
        };
        files.push(EvidenceFile {
            relative_path,
            size_bytes,
            content_sha256,
        });
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let completed_runs = repository
        .canonical_list_runs(None, 100)
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|run| run.state == RunState::Completed && run_matches_root(&run.target_label, root))
        .map(|run| RunEvidence {
            run_id: run.id.as_str().into(),
            kind: run.kind,
            target_label: run.target_label,
            completed_at_ms: run.updated_at_ms,
        })
        .collect();
    let mut collection_limits = vec![format!(
        "Evidence collection is path/metadata only, depth {MAX_WALK_DEPTH}, at most {MAX_EVIDENCE_FILES} files, with a 32 MiB hashing budget."
    )];
    if truncated {
        collection_limits.push("The file limit was reached; some paths were not evaluated.".into());
    }
    Ok(EvidenceSnapshot {
        root_label: root.to_string_lossy().into_owned(),
        files,
        completed_runs,
        collection_limits,
    })
}

fn ignored_entry(root: &Path, path: &Path) -> bool {
    if path == root {
        return false;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                ".git"
                    | ".hg"
                    | ".svn"
                    | "node_modules"
                    | "target"
                    | "dist"
                    | "build"
                    | ".venv"
                    | "vendor"
            )
        })
}

fn likely_evidence_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .is_some_and(|extension| {
            matches!(
                extension.as_str(),
                "md" | "txt"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "toml"
                    | "csv"
                    | "pdf"
                    | "doc"
                    | "docx"
                    | "xls"
                    | "xlsx"
                    | "html"
            )
        })
}

fn hash_file(root: &Path, path: &Path) -> Result<String, std::io::Error> {
    let canonical_before = path.canonicalize()?;
    if !canonical_before.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "evidence path escaped the selected project",
        ));
    }
    let mut file = File::open(&canonical_before)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "evidence path is not a regular file",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let canonical_after = path.canonicalize()?;
    if canonical_after != canonical_before || !canonical_after.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "evidence path changed while it was being hashed",
        ));
    }
    let current_metadata = canonical_after.metadata()?;
    if !same_file(&opened_metadata, &current_metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "evidence file changed while it was being hashed",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

fn run_matches_root(target_label: &str, root: &Path) -> bool {
    Path::new(target_label)
        .canonicalize()
        .map(|target| target == root || target.starts_with(root))
        .unwrap_or_else(|_| target_label == root.to_string_lossy())
}

fn safe_slug(value: &str) -> String {
    let slug = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    slug.split('-')
        .filter(|part| !part.is_empty())
        .take(8)
        .collect::<Vec<_>>()
        .join("-")
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_safe_and_bounded() {
        assert_eq!(safe_slug("ISO/SAE 21434:2021"), "iso-sae-21434-2021");
    }

    #[test]
    fn ignores_dependency_and_build_trees() {
        let root = Path::new("/project");
        assert!(ignored_entry(root, Path::new("/project/node_modules")));
        assert!(!ignored_entry(root, Path::new("/project/docs")));
    }
}
