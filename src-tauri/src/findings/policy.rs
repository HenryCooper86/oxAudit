use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{DateTime, SecondsFormat, Utc};
use ignore::gitignore::GitignoreBuilder;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    domain::{
        ReviewOrigin, ReviewRecord, ReviewRequest, ReviewState, FINGERPRINT_VERSION, POLICY_VERSION,
    },
    error::CommandError,
};
use crate::{
    models::Finding,
    triage::gates::{Gate, GateNote, GateVerdict},
};

pub use super::domain::PolicyStatus;

const INVALID_POLICY_MESSAGE: &str = "The project policy is invalid.";
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u16,
    pub entries: Vec<PolicyEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PolicyEntry {
    Finding {
        fingerprint_version: u16,
        fingerprint: String,
        category: String,
        state: ReviewState,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entry_point: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data_flow: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        gates: Vec<GateNote>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deciding_gate: Option<Gate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<String>,
    },
    Suppression {
        rule_id: String,
        path_pattern: String,
        state: ReviewState,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct LoadedPolicy {
    status: PolicyStatus,
    policy: Option<PolicyFile>,
}

impl LoadedPolicy {
    pub fn status(&self) -> &PolicyStatus {
        &self.status
    }

    pub fn policy(&self) -> Option<&PolicyFile> {
        self.policy.as_ref()
    }

    fn hash(&self) -> Option<&str> {
        match &self.status {
            PolicyStatus::Valid { hash } => Some(hash),
            PolicyStatus::Missing | PolicyStatus::Invalid { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValidationMode<'a> {
    Load,
    NewDecision(&'a DateTime<Utc>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteFailure {
    Never,
    AfterTempSync,
}

#[derive(Debug)]
struct InvalidPolicy;

static DRIVE_PREFIX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(^|[[:space:]=:('])(?:[a-z]:[/\\])").unwrap());
static ABSOLUTE_PATH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(^|[[:space:]=:(])/[A-Za-z0-9._-]").unwrap());
static LONG_TOKEN: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9_+./=-]{20,}").unwrap());

pub fn load_policy(project_root: impl AsRef<Path>) -> Result<LoadedPolicy, CommandError> {
    let policy_dir = project_root.as_ref().join(".oxaudit");
    let policy_path = policy_dir.join("policy.json");

    let directory_metadata = match fs::symlink_metadata(&policy_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(missing_policy()),
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Ok(invalid_loaded_policy());
    }

    let policy_metadata = match fs::symlink_metadata(&policy_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(missing_policy()),
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    if policy_metadata.file_type().is_symlink()
        || !policy_metadata.is_file()
        || policy_metadata.len() > MAX_POLICY_BYTES
    {
        return Ok(invalid_loaded_policy());
    }

    let bytes = match fs::read(&policy_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    match parse_and_validate(&bytes, ValidationMode::Load) {
        Ok(policy) => {
            let hash = hash_bytes(&bytes);
            Ok(LoadedPolicy {
                status: PolicyStatus::Valid { hash },
                policy: Some(policy),
            })
        }
        Err(_) => Ok(invalid_loaded_policy()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn apply_policy(
    loaded: &LoadedPolicy,
    project_id: &str,
    fingerprint_version: u16,
    fingerprint: &str,
    category: &str,
    rule_id: &str,
    relative_path: &str,
    local_active_review: Option<&ReviewRecord>,
    now: DateTime<Utc>,
) -> Result<ReviewRecord, CommandError> {
    if matches!(loaded.status(), PolicyStatus::Invalid { .. }) {
        return Err(CommandError::policy_invalid());
    }
    validate_observation_identity(
        fingerprint_version,
        fingerprint,
        category,
        rule_id,
        relative_path,
    )
    .map_err(|_| CommandError::policy_invalid())?;

    if let Some(local) = local_active_review.filter(|review| {
        review.origin == ReviewOrigin::Local
            && review.project_id == project_id
            && review.fingerprint_version == fingerprint_version
            && review.fingerprint == fingerprint
            && review.state != ReviewState::Candidate
            && review.superseded_at.is_none()
            && !is_expired(review.expires_at.as_deref(), &now)
    }) {
        return Ok(local.clone());
    }

    let Some(policy) = loaded.policy() else {
        return Ok(candidate_review(
            project_id,
            fingerprint_version,
            fingerprint,
            None,
            &now,
        ));
    };

    if let Some(entry) = policy.entries.iter().find(|entry| {
        matches!(entry, PolicyEntry::Finding {
            fingerprint_version: entry_version,
            fingerprint: entry_fingerprint,
            expires_at,
            ..
        } if *entry_version == fingerprint_version
            && entry_fingerprint == fingerprint
            && !is_expired(expires_at.as_deref(), &now))
    }) {
        if let PolicyEntry::Finding {
            category: entry_category,
            ..
        } = entry
        {
            if entry_category != category {
                return Err(CommandError::policy_invalid());
            }
        }
        return Ok(review_from_entry(
            entry,
            project_id,
            fingerprint_version,
            fingerprint,
            loaded.hash(),
            &now,
        ));
    }

    let mut matched = None;
    for entry in &policy.entries {
        let PolicyEntry::Suppression {
            rule_id: entry_rule,
            path_pattern,
            expires_at,
            ..
        } = entry
        else {
            continue;
        };
        if entry_rule == rule_id
            && !is_expired(expires_at.as_deref(), &now)
            && pattern_matches(path_pattern, relative_path)
                .map_err(|_| CommandError::policy_invalid())?
        {
            matched = Some(entry);
        }
    }

    Ok(matched.map_or_else(
        || {
            candidate_review(
                project_id,
                fingerprint_version,
                fingerprint,
                loaded.hash(),
                &now,
            )
        },
        |entry| {
            review_from_entry(
                entry,
                project_id,
                fingerprint_version,
                fingerprint,
                loaded.hash(),
                &now,
            )
        },
    ))
}

pub fn update_policy_decision(
    project_root: impl AsRef<Path>,
    finding: &Finding,
    request: &ReviewRequest,
    now: DateTime<Utc>,
) -> Result<ReviewRecord, CommandError> {
    update_policy_decision_with_hook(project_root, finding, request, now, WriteFailure::Never)
}

fn update_policy_decision_with_hook(
    project_root: impl AsRef<Path>,
    finding: &Finding,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    failure: WriteFailure,
) -> Result<ReviewRecord, CommandError> {
    validate_update_input(finding, request, &now).map_err(|_| CommandError::review_invalid())?;

    let project_root = project_root.as_ref();
    let loaded = load_policy(project_root)?;
    let mut policy = match loaded.status() {
        PolicyStatus::Missing => PolicyFile {
            version: POLICY_VERSION,
            entries: Vec::new(),
        },
        PolicyStatus::Valid { .. } => loaded
            .policy()
            .cloned()
            .ok_or_else(CommandError::policy_invalid)?,
        PolicyStatus::Invalid { .. } => return Err(CommandError::policy_invalid()),
    };

    let matching_entry = |entry: &PolicyEntry| {
        matches!(entry, PolicyEntry::Finding {
            fingerprint_version,
            fingerprint,
            ..
        } if *fingerprint_version == finding.fingerprint_version
            && fingerprint == &finding.fingerprint)
    };

    if request.state == ReviewState::Candidate {
        policy.entries.retain(|entry| !matching_entry(entry));
    } else {
        let new_entry = entry_from_update(finding, request);
        validate_entry(&new_entry, ValidationMode::NewDecision(&now))
            .map_err(|_| CommandError::review_invalid())?;
        if let Some(index) = policy.entries.iter().position(matching_entry) {
            policy.entries[index] = new_entry;
        } else {
            policy.entries.push(new_entry);
        }
    }
    validate_policy(&policy, ValidationMode::Load).map_err(|_| CommandError::review_invalid())?;

    let mut bytes =
        serde_json::to_vec_pretty(&policy).map_err(|_| CommandError::policy_write_failed())?;
    bytes.push(b'\n');
    atomic_write_policy(project_root, &bytes, failure)?;

    let reloaded = load_policy(project_root)?;
    if !matches!(reloaded.status(), PolicyStatus::Valid { .. }) {
        return Err(CommandError::policy_write_failed());
    }
    apply_policy(
        &reloaded,
        &request.project_id,
        finding.fingerprint_version,
        &finding.fingerprint,
        &finding.category,
        &finding.rule_id,
        &finding.file_path,
        None,
        now,
    )
}

fn parse_and_validate(bytes: &[u8], mode: ValidationMode<'_>) -> Result<PolicyFile, InvalidPolicy> {
    let raw: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| InvalidPolicy)?;
    validate_closed_schema(&raw)?;
    let policy: PolicyFile = serde_json::from_value(raw).map_err(|_| InvalidPolicy)?;
    validate_policy(&policy, mode)?;
    Ok(policy)
}

fn validate_closed_schema(raw: &serde_json::Value) -> Result<(), InvalidPolicy> {
    let root = raw.as_object().ok_or(InvalidPolicy)?;
    require_exact_keys(root, &["version", "entries"])?;
    let entries = root
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or(InvalidPolicy)?;
    for entry in entries {
        let entry = entry.as_object().ok_or(InvalidPolicy)?;
        match entry.get("kind").and_then(serde_json::Value::as_str) {
            Some("finding") => {
                require_allowed_keys(
                    entry,
                    &[
                        "kind",
                        "fingerprintVersion",
                        "fingerprint",
                        "category",
                        "state",
                        "reason",
                        "evidence",
                        "entryPoint",
                        "dataFlow",
                        "gates",
                        "decidingGate",
                        "expiresAt",
                    ],
                )?;
                for required in [
                    "fingerprintVersion",
                    "fingerprint",
                    "category",
                    "state",
                    "reason",
                ] {
                    if !entry.contains_key(required) {
                        return Err(InvalidPolicy);
                    }
                }
                if let Some(gates) = entry.get("gates") {
                    for gate in gates.as_array().ok_or(InvalidPolicy)? {
                        let gate = gate.as_object().ok_or(InvalidPolicy)?;
                        require_exact_keys(gate, &["gate", "verdict", "evidence"])?;
                    }
                }
            }
            Some("suppression") => {
                require_allowed_keys(
                    entry,
                    &[
                        "kind",
                        "ruleId",
                        "pathPattern",
                        "state",
                        "reason",
                        "expiresAt",
                    ],
                )?;
                for required in ["ruleId", "pathPattern", "state", "reason"] {
                    if !entry.contains_key(required) {
                        return Err(InvalidPolicy);
                    }
                }
            }
            _ => return Err(InvalidPolicy),
        }
    }
    Ok(())
}

fn require_exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Result<(), InvalidPolicy> {
    if object.len() != keys.len() || object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(InvalidPolicy);
    }
    Ok(())
}

fn require_allowed_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Result<(), InvalidPolicy> {
    if object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(InvalidPolicy);
    }
    Ok(())
}

fn validate_policy(policy: &PolicyFile, mode: ValidationMode<'_>) -> Result<(), InvalidPolicy> {
    if policy.version != POLICY_VERSION {
        return Err(InvalidPolicy);
    }
    let mut identities = HashSet::new();
    for entry in &policy.entries {
        validate_entry(entry, mode)?;
        if let PolicyEntry::Finding {
            fingerprint_version,
            fingerprint,
            ..
        } = entry
        {
            if !identities.insert((*fingerprint_version, fingerprint.as_str())) {
                return Err(InvalidPolicy);
            }
        }
    }
    Ok(())
}

fn validate_entry(entry: &PolicyEntry, mode: ValidationMode<'_>) -> Result<(), InvalidPolicy> {
    match entry {
        PolicyEntry::Finding {
            fingerprint_version,
            fingerprint,
            category,
            state,
            reason,
            evidence,
            entry_point,
            data_flow,
            gates,
            deciding_gate,
            expires_at,
        } => {
            if *fingerprint_version != FINGERPRINT_VERSION || !valid_fingerprint(fingerprint) {
                return Err(InvalidPolicy);
            }
            validate_finding_decision(
                category,
                *state,
                reason,
                evidence.as_deref(),
                entry_point.as_deref(),
                data_flow.as_deref(),
                gates,
                *deciding_gate,
                expires_at.as_deref(),
                mode,
            )?;
        }
        PolicyEntry::Suppression {
            rule_id,
            path_pattern,
            state,
            reason,
            expires_at,
        } => {
            if *state != ReviewState::Suppressed
                || !valid_rule_id(rule_id)
                || !safe_pattern(path_pattern)
                || !safe_required_text(reason)
            {
                return Err(InvalidPolicy);
            }
            validate_expiry(expires_at.as_deref(), mode)?;
            let mut builder = GitignoreBuilder::new("");
            builder
                .add_line(None, path_pattern)
                .map_err(|_| InvalidPolicy)?;
            builder.build().map_err(|_| InvalidPolicy)?;
        }
    }
    Ok(())
}

fn validate_update_input(
    finding: &Finding,
    request: &ReviewRequest,
    now: &DateTime<Utc>,
) -> Result<(), InvalidPolicy> {
    validate_observation_identity(
        finding.fingerprint_version,
        &finding.fingerprint,
        &finding.category,
        &finding.rule_id,
        &finding.file_path,
    )?;
    if request.origin != ReviewOrigin::ProjectPolicy
        || request.fingerprint_version != finding.fingerprint_version
        || request.fingerprint != finding.fingerprint
        || request.category != finding.category
    {
        return Err(InvalidPolicy);
    }
    if request.state == ReviewState::Candidate {
        if !request.reason.trim().is_empty()
            || request.evidence.is_some()
            || request.entry_point.is_some()
            || request.data_flow.is_some()
            || !request.gates.is_empty()
            || request.deciding_gate.is_some()
            || request.expires_at.is_some()
        {
            return Err(InvalidPolicy);
        }
        return Ok(());
    }
    validate_finding_decision(
        &finding.category,
        request.state,
        &request.reason,
        request.evidence.as_deref(),
        request.entry_point.as_deref(),
        request.data_flow.as_deref(),
        &request.gates,
        request.deciding_gate,
        request.expires_at.as_deref(),
        ValidationMode::NewDecision(now),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_finding_decision(
    category: &str,
    state: ReviewState,
    reason: &str,
    evidence: Option<&str>,
    entry_point: Option<&str>,
    data_flow: Option<&str>,
    gates: &[GateNote],
    deciding_gate: Option<Gate>,
    expires_at: Option<&str>,
    mode: ValidationMode<'_>,
) -> Result<(), InvalidPolicy> {
    if !matches!(category, "secret" | "vulnerability")
        || !portable_state(state)
        || !safe_required_text(reason)
    {
        return Err(InvalidPolicy);
    }
    validate_expiry(expires_at, mode)?;
    for value in [evidence, entry_point, data_flow].into_iter().flatten() {
        if !safe_required_text(value) {
            return Err(InvalidPolicy);
        }
    }
    match (category, state) {
        ("vulnerability", ReviewState::FalsePositive) => {
            if gates.len() != 1 {
                return Err(InvalidPolicy);
            }
            let deciding_gate = deciding_gate.ok_or(InvalidPolicy)?;
            let note = &gates[0];
            if note.gate != deciding_gate
                || note.verdict != GateVerdict::Eliminates
                || !safe_required_text(&note.evidence)
            {
                return Err(InvalidPolicy);
            }
        }
        ("vulnerability", ReviewState::AcceptedRisk | ReviewState::Suppressed) | ("secret", _) => {
            if evidence.is_some()
                || entry_point.is_some()
                || data_flow.is_some()
                || !gates.is_empty()
                || deciding_gate.is_some()
            {
                return Err(InvalidPolicy);
            }
        }
        _ => return Err(InvalidPolicy),
    }
    Ok(())
}

fn validate_observation_identity(
    fingerprint_version: u16,
    fingerprint: &str,
    category: &str,
    rule_id: &str,
    relative_path: &str,
) -> Result<(), InvalidPolicy> {
    if fingerprint_version != FINGERPRINT_VERSION
        || !valid_fingerprint(fingerprint)
        || !matches!(category, "secret" | "vulnerability")
        || !valid_rule_id(rule_id)
        || !safe_relative_path(relative_path)
    {
        return Err(InvalidPolicy);
    }
    Ok(())
}

fn entry_from_update(finding: &Finding, request: &ReviewRequest) -> PolicyEntry {
    PolicyEntry::Finding {
        fingerprint_version: finding.fingerprint_version,
        fingerprint: finding.fingerprint.clone(),
        category: finding.category.clone(),
        state: request.state,
        reason: request.reason.clone(),
        evidence: request.evidence.clone(),
        entry_point: request.entry_point.clone(),
        data_flow: request.data_flow.clone(),
        gates: request.gates.clone(),
        deciding_gate: request.deciding_gate,
        expires_at: request.expires_at.clone(),
    }
}

fn portable_state(state: ReviewState) -> bool {
    matches!(
        state,
        ReviewState::FalsePositive | ReviewState::AcceptedRisk | ReviewState::Suppressed
    )
}

fn validate_expiry(value: Option<&str>, mode: ValidationMode<'_>) -> Result<(), InvalidPolicy> {
    let Some(value) = value else {
        return Ok(());
    };
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| InvalidPolicy)?
        .with_timezone(&Utc);
    if let ValidationMode::NewDecision(now) = mode {
        if parsed <= *now {
            return Err(InvalidPolicy);
        }
    }
    Ok(())
}

fn safe_required_text(value: &str) -> bool {
    !value.trim().is_empty() && safe_optional_text(value)
}

fn safe_optional_text(value: &str) -> bool {
    !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !value.contains("[REDACTED]")
        && !contains_absolute_or_traversal(value)
        && !credential_shaped(value)
}

fn contains_absolute_or_traversal(value: &str) -> bool {
    if DRIVE_PREFIX.is_match(value) || ABSOLUTE_PATH.is_match(value) {
        return true;
    }
    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|character: char| {
            matches!(
                character,
                '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '\'' | '"'
            )
        });
        token.starts_with('/')
            || token == ".."
            || token.starts_with("../")
            || token.ends_with("/..")
            || token.contains("/../")
    })
}

fn credential_shaped(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("-----begin ")
        || lower.contains("authorization: bearer")
        || lower.contains("password=")
        || lower.contains("password:")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
        || lower.contains("secret=")
        || lower.contains("token=")
        || (lower.contains("://") && lower.contains('@'))
    {
        return true;
    }
    LONG_TOKEN.find_iter(value).any(|candidate| {
        let candidate = candidate.as_str();
        candidate
            .chars()
            .any(|character| character.is_ascii_digit())
            && candidate
                .chars()
                .any(|character| character.is_ascii_alphabetic())
    })
}

fn valid_fingerprint(value: &str) -> bool {
    let (digest, occurrence) = value
        .split_once(':')
        .map_or((value, None), |(digest, occurrence)| {
            (digest, Some(occurrence))
        });
    (6..=128).contains(&digest.len())
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        && occurrence.is_none_or(|occurrence| {
            !occurrence.is_empty()
                && occurrence
                    .chars()
                    .all(|character| character.is_ascii_digit())
        })
}

fn valid_rule_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !has_drive_prefix(value)
        && !value
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
}

fn safe_pattern(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.starts_with('/')
        && !value.starts_with('!')
        && !value.starts_with('#')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !has_drive_prefix(value)
        && !value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
}

fn has_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_expired(value: Option<&str>, now: &DateTime<Utc>) -> bool {
    value.is_some_and(|value| {
        DateTime::parse_from_rfc3339(value)
            .map(|value| value.with_timezone(&Utc) <= *now)
            .unwrap_or(true)
    })
}

fn pattern_matches(pattern: &str, relative_path: &str) -> Result<bool, InvalidPolicy> {
    let mut builder = GitignoreBuilder::new("");
    builder.add_line(None, pattern).map_err(|_| InvalidPolicy)?;
    let matcher = builder.build().map_err(|_| InvalidPolicy)?;
    Ok(matcher
        .matched_path_or_any_parents(Path::new(relative_path), false)
        .is_ignore())
}

fn candidate_review(
    project_id: &str,
    fingerprint_version: u16,
    fingerprint: &str,
    policy_hash: Option<&str>,
    now: &DateTime<Utc>,
) -> ReviewRecord {
    ReviewRecord {
        id: format!("project-policy:{fingerprint_version}:{fingerprint}"),
        project_id: project_id.to_owned(),
        fingerprint_version,
        fingerprint: fingerprint.to_owned(),
        state: ReviewState::Candidate,
        reason: String::new(),
        evidence: None,
        entry_point: None,
        data_flow: None,
        gates: Vec::new(),
        deciding_gate: None,
        expires_at: None,
        origin: ReviewOrigin::ProjectPolicy,
        policy_hash: policy_hash.map(str::to_owned),
        updated_at: timestamp(now),
        superseded_at: None,
    }
}

fn review_from_entry(
    entry: &PolicyEntry,
    project_id: &str,
    fingerprint_version: u16,
    fingerprint: &str,
    policy_hash: Option<&str>,
    now: &DateTime<Utc>,
) -> ReviewRecord {
    let (state, reason, evidence, entry_point, data_flow, gates, deciding_gate, expires_at) =
        match entry {
            PolicyEntry::Finding {
                state,
                reason,
                evidence,
                entry_point,
                data_flow,
                gates,
                deciding_gate,
                expires_at,
                ..
            } => (
                *state,
                reason.clone(),
                evidence.clone(),
                entry_point.clone(),
                data_flow.clone(),
                gates.clone(),
                *deciding_gate,
                expires_at.clone(),
            ),
            PolicyEntry::Suppression {
                state,
                reason,
                expires_at,
                ..
            } => (
                *state,
                reason.clone(),
                None,
                None,
                None,
                Vec::new(),
                None,
                expires_at.clone(),
            ),
        };
    ReviewRecord {
        id: format!("project-policy:{fingerprint_version}:{fingerprint}"),
        project_id: project_id.to_owned(),
        fingerprint_version,
        fingerprint: fingerprint.to_owned(),
        state,
        reason,
        evidence,
        entry_point,
        data_flow,
        gates,
        deciding_gate,
        expires_at,
        origin: ReviewOrigin::ProjectPolicy,
        policy_hash: policy_hash.map(str::to_owned),
        updated_at: timestamp(now),
        superseded_at: None,
    }
}

fn atomic_write_policy(
    project_root: &Path,
    bytes: &[u8],
    failure: WriteFailure,
) -> Result<(), CommandError> {
    let policy_dir = project_root.join(".oxaudit");
    ensure_real_policy_directory(&policy_dir)?;
    let policy_path = policy_dir.join("policy.json");
    ensure_regular_or_missing(&policy_path)?;

    let temp_path = policy_dir.join(format!(".policy.json.{}.tmp", Uuid::new_v4()));
    let mut cleanup = OwnedTemp::new(temp_path.clone());
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|_| CommandError::policy_write_failed())?;
    temp.write_all(bytes)
        .and_then(|_| temp.flush())
        .and_then(|_| temp.sync_all())
        .map_err(|_| CommandError::policy_write_failed())?;
    if failure == WriteFailure::AfterTempSync {
        return Err(CommandError::policy_write_failed());
    }

    let persisted = fs::read(&temp_path).map_err(|_| CommandError::policy_write_failed())?;
    parse_and_validate(&persisted, ValidationMode::Load)
        .map_err(|_| CommandError::policy_write_failed())?;
    if persisted != bytes {
        return Err(CommandError::policy_write_failed());
    }

    ensure_real_policy_directory(&policy_dir)?;
    ensure_regular_or_missing(&policy_path)?;
    fs::rename(&temp_path, &policy_path).map_err(|_| CommandError::policy_write_failed())?;
    cleanup.committed = true;

    #[cfg(unix)]
    File::open(&policy_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CommandError::policy_write_failed())?;
    Ok(())
}

fn ensure_real_policy_directory(path: &Path) -> Result<(), CommandError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(CommandError::policy_write_failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| CommandError::policy_write_failed())?;
            let metadata =
                fs::symlink_metadata(path).map_err(|_| CommandError::policy_write_failed())?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(CommandError::policy_write_failed())
            }
        }
        Err(_) => Err(CommandError::policy_write_failed()),
    }
}

fn ensure_regular_or_missing(path: &Path) -> Result<(), CommandError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(CommandError::policy_write_failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CommandError::policy_write_failed()),
    }
}

struct OwnedTemp {
    path: PathBuf,
    committed: bool,
}

impl OwnedTemp {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }
}

impl Drop for OwnedTemp {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn missing_policy() -> LoadedPolicy {
    LoadedPolicy {
        status: PolicyStatus::Missing,
        policy: None,
    }
}

fn invalid_loaded_policy() -> LoadedPolicy {
    LoadedPolicy {
        status: PolicyStatus::Invalid {
            message: INVALID_POLICY_MESSAGE.to_owned(),
        },
        policy: None,
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn timestamp(now: &DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use chrono::{TimeZone, Utc};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        findings::domain::{
            PolicyStatus, ReviewOrigin, ReviewRecord, ReviewRequest, ReviewState,
            FINGERPRINT_VERSION,
        },
        models::Finding,
        triage::gates::{Gate, GateNote, GateVerdict},
    };

    const CANARY: &str = "oxaudit-secret-canary-7D4zP9q2";
    const VALID_POLICY: &str = r#"{
  "version": 1,
  "entries": [
    {
      "kind": "finding",
      "fingerprintVersion": 1,
      "fingerprint": "abc123",
      "category": "vulnerability",
      "state": "falsePositive",
      "reason": "The affected branch is excluded from production",
      "gates": [
        {
          "gate": "reachable",
          "verdict": "eliminates",
          "evidence": "The production feature manifest excludes this branch"
        }
      ],
      "decidingGate": "reachable"
    },
    {
      "kind": "suppression",
      "ruleId": "gen-hardcoded-password",
      "pathPattern": "tests/**",
      "state": "suppressed",
      "reason": "Synthetic credential fixtures",
      "expiresAt": "2027-01-01T00:00:00Z"
    }
  ]
}"#;

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0)
            .single()
            .unwrap()
    }

    fn write_policy(root: &Path, bytes: &[u8]) {
        fs::create_dir_all(root.join(".oxaudit")).unwrap();
        fs::write(root.join(".oxaudit/policy.json"), bytes).unwrap();
    }

    fn load_json(root: &Path, json: serde_json::Value) -> LoadedPolicy {
        write_policy(
            root,
            serde_json::to_string_pretty(&json).unwrap().as_bytes(),
        );
        load_policy(root).unwrap()
    }

    fn status_hash(loaded: &LoadedPolicy) -> Option<&str> {
        match loaded.status() {
            PolicyStatus::Valid { hash } => Some(hash),
            _ => None,
        }
    }

    fn apply(
        loaded: &LoadedPolicy,
        fingerprint: &str,
        category: &str,
        rule_id: &str,
        path: &str,
        local: Option<&ReviewRecord>,
    ) -> Result<ReviewRecord, crate::findings::error::CommandError> {
        apply_policy(
            loaded,
            "project-1",
            FINGERPRINT_VERSION,
            fingerprint,
            category,
            rule_id,
            path,
            local,
            now(),
        )
    }

    fn finding(category: &str) -> Finding {
        Finding {
            id: "observation-1".into(),
            category: category.into(),
            rule_id: "generic-api-key".into(),
            rule_name: format!("rule {CANARY}"),
            severity: "high".into(),
            title: format!("title {CANARY}"),
            description: format!("description {CANARY}"),
            file_path: "src/config.rs".into(),
            line: 8,
            column: 17,
            match_text: format!("token = {CANARY}"),
            context: format!("let token = \"{CANARY}\";"),
            language: "rust".into(),
            cwe: Some("CWE-798".into()),
            cwe_exploited: false,
            cwe_exploited_count: 0,
            recommendation: format!("rotate {CANARY}"),
            entropy: Some(4.95),
            verified: None,
            observation_run_id: format!("run-{CANARY}"),
            resolved_by_run_id: None,
            fingerprint_version: FINGERPRINT_VERSION,
            fingerprint: "abcdef0123456789".into(),
            scope: None,
            scope_reason: Some(format!("scope {CANARY}")),
            review: None,
            review_history: Vec::new(),
            diff_status: None,
        }
    }

    fn request(state: ReviewState, category: &str) -> ReviewRequest {
        ReviewRequest {
            project_id: "project-1".into(),
            fingerprint_version: FINGERPRINT_VERSION,
            fingerprint: "abcdef0123456789".into(),
            category: category.into(),
            state,
            reason: "Reviewed by the application security team".into(),
            evidence: None,
            entry_point: None,
            data_flow: None,
            gates: Vec::new(),
            deciding_gate: None,
            expires_at: Some("2027-01-01T00:00:00Z".into()),
            origin: ReviewOrigin::ProjectPolicy,
        }
    }

    fn local_review() -> ReviewRecord {
        ReviewRecord {
            id: "local-review".into(),
            project_id: "project-1".into(),
            fingerprint_version: FINGERPRINT_VERSION,
            fingerprint: "abc123".into(),
            state: ReviewState::AcceptedRisk,
            reason: "Local decision".into(),
            evidence: None,
            entry_point: None,
            data_flow: None,
            gates: Vec::new(),
            deciding_gate: None,
            expires_at: None,
            origin: ReviewOrigin::Local,
            policy_hash: None,
            updated_at: "2026-08-20T00:00:00Z".into(),
            superseded_at: None,
        }
    }

    #[test]
    fn missing_policy_has_an_explicit_missing_status() {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_policy(root.path()).unwrap();
        assert_eq!(loaded.status(), &PolicyStatus::Missing);
        assert!(loaded.policy().is_none());
    }

    #[test]
    fn valid_policy_hashes_the_exact_authoritative_bytes_and_is_stable_on_reload() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), VALID_POLICY.as_bytes());
        let expected = format!("{:x}", Sha256::digest(VALID_POLICY.as_bytes()));

        let first = load_policy(root.path()).unwrap();
        let second = load_policy(root.path()).unwrap();

        assert_eq!(status_hash(&first), Some(expected.as_str()));
        assert_eq!(status_hash(&second), Some(expected.as_str()));
        assert_eq!(first.policy().unwrap().entries.len(), 2);
    }

    #[test]
    fn invalid_schema_is_reported_with_one_fixed_safe_status_and_preserved() {
        let invalid_cases = [
            serde_json::json!({"version": 2, "entries": []}),
            serde_json::json!({"version": 1, "entries": [], "unknown": "private"}),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "suppressed", "reason": "valid", "context": CANARY
            }]}),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "suppressed"
            }]}),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "suppressed", "reason": "   "
            }]}),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "candidate", "reason": "not portable"
            }]}),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "vulnerability", "state": "confirmed", "reason": "local only"
            }]}),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "suppressed", "reason": "valid", "expiresAt": "tomorrow"
            }]}),
        ];

        for (index, policy) in invalid_cases.into_iter().enumerate() {
            let root = tempfile::tempdir().unwrap();
            let bytes = serde_json::to_vec(&policy).unwrap();
            write_policy(root.path(), &bytes);
            let loaded = load_policy(root.path()).unwrap();
            assert_eq!(
                loaded.status(),
                &PolicyStatus::Invalid {
                    message: "The project policy is invalid.".into()
                },
                "case {index}"
            );
            assert!(loaded.policy().is_none(), "case {index}");
            assert_eq!(
                fs::read(root.path().join(".oxaudit/policy.json")).unwrap(),
                bytes,
                "case {index}"
            );
        }
    }

    #[test]
    fn nonportable_and_unsafe_patterns_are_rejected_without_normalization() {
        for pattern in [
            "/tests/**",
            "C:/tests/**",
            "C:tests/**",
            "C:\\tests\\**",
            "tests/../src/**",
            "tests\\**",
            "!tests/private/**",
            "#tests/private/**",
            "   ",
            "",
        ] {
            let root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                root.path(),
                serde_json::json!({"version": 1, "entries": [{
                    "kind": "suppression", "ruleId": "rule", "pathPattern": pattern,
                    "state": "suppressed", "reason": "Fixture policy"
                }]}),
            );
            assert!(
                matches!(loaded.status(), PolicyStatus::Invalid { .. }),
                "{pattern}"
            );
        }
    }

    #[test]
    fn category_state_evidence_matrix_is_strict() {
        let invalid_entries = [
            serde_json::json!({
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "secret", "state": "falsePositive", "reason": "Fixture",
                "evidence": "safe-looking evidence"
            }),
            serde_json::json!({
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "secret", "state": "falsePositive", "reason": "Fixture",
                "gates": [{"gate": "reachable", "verdict": "eliminates", "evidence": "Fixture only"}],
                "decidingGate": "reachable"
            }),
            serde_json::json!({
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "vulnerability", "state": "falsePositive", "reason": "Fixture"
            }),
            serde_json::json!({
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "vulnerability", "state": "falsePositive", "reason": "Fixture",
                "gates": [{"gate": "reachable", "verdict": "survives", "evidence": "Reachable"}],
                "decidingGate": "reachable"
            }),
            serde_json::json!({
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "vulnerability", "state": "acceptedRisk", "reason": "Accepted",
                "gates": [{"gate": "reachable", "verdict": "eliminates", "evidence": "Not allowed"}],
                "decidingGate": "reachable"
            }),
            serde_json::json!({
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "other", "state": "acceptedRisk", "reason": "Unknown category"
            }),
        ];
        for (index, entry) in invalid_entries.into_iter().enumerate() {
            let root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                root.path(),
                serde_json::json!({"version": 1, "entries": [entry]}),
            );
            assert!(
                matches!(loaded.status(), PolicyStatus::Invalid { .. }),
                "case {index}"
            );
        }
    }

    #[test]
    fn path_and_credential_shaped_evidence_is_rejected_safely() {
        for evidence in [
            "/Users/alice/private/source.rs:9",
            "verified path=/etc/passwd",
            "C:\\private\\source.rs:9",
            "checked at src/../private.rs:9",
            "Authorization: Bearer ghp_1234567890abcdefghijklmnop",
            "const value = input();\nexecute(value);",
            CANARY,
        ] {
            let root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                root.path(),
                serde_json::json!({"version": 1, "entries": [{
                    "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                    "category": "vulnerability", "state": "falsePositive", "reason": "Excluded",
                    "gates": [{"gate": "reachable", "verdict": "eliminates", "evidence": evidence}],
                    "decidingGate": "reachable"
                }]}),
            );
            assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
        }
    }

    #[test]
    fn expired_entries_are_retained_but_do_not_apply() {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "secret", "state": "acceptedRisk", "reason": "Temporary",
                "expiresAt": "2026-01-01T00:00:00Z"
            }, {
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "suppressed", "reason": "Temporary fixtures",
                "expiresAt": "2026-01-01T00:00:00Z"
            }]}),
        );
        assert_eq!(loaded.policy().unwrap().entries.len(), 2);
        let review = apply(&loaded, "abc123", "secret", "rule", "tests/a.rs", None).unwrap();
        assert_eq!(review.state, ReviewState::Candidate);
    }

    #[test]
    fn precedence_is_local_then_exact_then_last_suppression_then_candidate() {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "suppressed", "reason": "First suppression"
            }, {
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "secret", "state": "acceptedRisk", "reason": "Exact decision"
            }, {
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/unit/**",
                "state": "suppressed", "reason": "Last suppression"
            }]}),
        );

        let local = local_review();
        assert_eq!(
            apply(
                &loaded,
                "abc123",
                "secret",
                "rule",
                "tests/unit/a.rs",
                Some(&local)
            )
            .unwrap()
            .reason,
            "Local decision"
        );
        let exact = apply(&loaded, "abc123", "secret", "rule", "tests/unit/a.rs", None).unwrap();
        assert_eq!(exact.reason, "Exact decision");
        assert_eq!(exact.origin, ReviewOrigin::ProjectPolicy);
        assert_eq!(exact.policy_hash.as_deref(), status_hash(&loaded));
        let suppression =
            apply(&loaded, "def456", "secret", "rule", "tests/unit/a.rs", None).unwrap();
        assert_eq!(suppression.reason, "Last suppression");
        let candidate = apply(&loaded, "def456", "secret", "other", "src/a.rs", None).unwrap();
        assert_eq!(candidate.state, ReviewState::Candidate);
    }

    #[test]
    fn exact_fingerprint_category_mismatch_is_invalid_and_never_falls_through() {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "vulnerability", "state": "acceptedRisk", "reason": "Exact"
            }, {
                "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
                "state": "suppressed", "reason": "Weaker suppression"
            }]}),
        );
        let error = apply(&loaded, "abc123", "secret", "rule", "tests/a.rs", None).unwrap_err();
        assert_eq!(error.code, crate::findings::error::ErrorCode::PolicyInvalid);
        assert_eq!(error.message, "The project policy is invalid.");
        assert!(error.detail.is_none());
    }

    #[test]
    fn unsafe_observation_paths_are_rejected_instead_of_normalized() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let loaded = load_policy(root.path()).unwrap();
        for path in [
            "/src/a.rs",
            "C:/src/a.rs",
            "C:src/a.rs",
            "src/../a.rs",
            "src\\a.rs",
        ] {
            assert!(apply(&loaded, "abc123", "secret", "rule", path, None).is_err());
        }
    }

    #[test]
    fn update_is_allowlisted_and_never_serializes_finding_canaries() {
        let root = tempfile::tempdir().unwrap();
        let finding = finding("secret");
        let request = request(ReviewState::FalsePositive, "secret");

        let review = update_policy_decision(root.path(), &finding, &request, now()).unwrap();
        let bytes = fs::read(root.path().join(".oxaudit/policy.json")).unwrap();
        let serialized = String::from_utf8(bytes.clone()).unwrap();

        assert!(!serialized.contains(CANARY));
        for forbidden in [
            "matchText",
            "context",
            "title",
            "description",
            "recommendation",
            "entropy",
            "observationRunId",
            "scopeReason",
        ] {
            assert!(!serialized.contains(forbidden), "serialized {forbidden}");
        }
        assert!(serialized.ends_with('\n'));
        assert!(serialized.contains("\n  \"entries\": ["));
        let expected_hash = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(review.policy_hash.as_deref(), Some(expected_hash.as_str()));
        assert_eq!(
            status_hash(&load_policy(root.path()).unwrap()),
            Some(expected_hash.as_str())
        );
    }

    #[test]
    fn update_rejects_identity_mismatch_credentials_and_nonfuture_expiry() {
        let root = tempfile::tempdir().unwrap();
        let finding = finding("secret");

        let mut mismatch = request(ReviewState::FalsePositive, "secret");
        mismatch.fingerprint = "deadbeef".into();
        assert!(update_policy_decision(root.path(), &finding, &mismatch, now()).is_err());

        let mut credential = request(ReviewState::FalsePositive, "secret");
        credential.reason = format!("Copied token {CANARY}");
        assert!(update_policy_decision(root.path(), &finding, &credential, now()).is_err());

        let mut expired = request(ReviewState::FalsePositive, "secret");
        expired.expires_at = Some("2026-08-21T11:59:59Z".into());
        assert!(update_policy_decision(root.path(), &finding, &expired, now()).is_err());
        assert!(!root.path().join(".oxaudit/policy.json").exists());
    }

    #[test]
    fn vulnerability_false_positive_round_trips_one_eliminating_gate() {
        let root = tempfile::tempdir().unwrap();
        let finding = finding("vulnerability");
        let mut request = request(ReviewState::FalsePositive, "vulnerability");
        request.gates = vec![GateNote {
            gate: Gate::Reachable,
            verdict: GateVerdict::Eliminates,
            evidence: "The production manifest excludes src/dev.rs:8".into(),
        }];
        request.deciding_gate = Some(Gate::Reachable);

        let review = update_policy_decision(root.path(), &finding, &request, now()).unwrap();
        assert_eq!(review.gates, request.gates);
        assert_eq!(review.deciding_gate, Some(Gate::Reachable));

        let loaded = load_policy(root.path()).unwrap();
        let applied = apply(
            &loaded,
            &finding.fingerprint,
            "vulnerability",
            &finding.rule_id,
            &finding.file_path,
            None,
        )
        .unwrap();
        assert_eq!(applied.gates, request.gates);
        assert_eq!(applied.deciding_gate, Some(Gate::Reachable));
    }

    #[test]
    fn vulnerability_false_positive_retains_only_sanitized_review_evidence_fields() {
        let root = tempfile::tempdir().unwrap();
        let finding = finding("vulnerability");
        let mut request = request(ReviewState::FalsePositive, "vulnerability");
        request.evidence = Some("The production manifest excludes the development route".into());
        request.entry_point = Some("src/router.rs:18".into());
        request.data_flow = Some("router -> development handler".into());
        request.gates = vec![GateNote {
            gate: Gate::Reachable,
            verdict: GateVerdict::Eliminates,
            evidence: "The production manifest excludes src/dev.rs:8".into(),
        }];
        request.deciding_gate = Some(Gate::Reachable);

        let review = update_policy_decision(root.path(), &finding, &request, now()).unwrap();

        assert_eq!(review.evidence, request.evidence);
        assert_eq!(review.entry_point, request.entry_point);
        assert_eq!(review.data_flow, request.data_flow);
    }

    #[test]
    fn invalid_existing_policy_is_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let original = br#"{"version":999,"private":"do not replace"}"#;
        write_policy(root.path(), original);
        let error = update_policy_decision(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
        )
        .unwrap_err();
        assert_eq!(error.code, crate::findings::error::ErrorCode::PolicyInvalid);
        assert_eq!(
            fs::read(root.path().join(".oxaudit/policy.json")).unwrap(),
            original
        );
    }

    #[test]
    fn injected_failure_preserves_prior_bytes_and_cleans_only_its_temp() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let original = fs::read(&policy_path).unwrap();
        let stale = root.path().join(".oxaudit/.policy.json.stale.tmp");
        fs::write(&stale, b"unrelated").unwrap();

        let error = update_policy_decision_with_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterTempSync,
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(&policy_path).unwrap(), original);
        assert_eq!(fs::read(&stale).unwrap(), b"unrelated");
        let owned_temps = fs::read_dir(root.path().join(".oxaudit"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".policy.json.") && name != ".policy.json.stale.tmp"
            })
            .count();
        assert_eq!(owned_temps, 0);
    }

    #[cfg(unix)]
    #[test]
    fn writes_reject_symlink_and_non_directory_escape_surfaces() {
        use std::os::unix::fs::symlink;

        let outer = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), outer.path().join(".oxaudit")).unwrap();
        assert!(update_policy_decision(
            outer.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
        )
        .is_err());
        assert!(!target.path().join("policy.json").exists());

        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".oxaudit")).unwrap();
        let outside = root.path().join("outside.json");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.path().join(".oxaudit/policy.json")).unwrap();
        assert!(update_policy_decision(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
        )
        .is_err());
        assert_eq!(fs::read(outside).unwrap(), b"outside");

        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(".oxaudit"), b"not a directory").unwrap();
        assert!(update_policy_decision(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
        )
        .is_err());
    }
}
