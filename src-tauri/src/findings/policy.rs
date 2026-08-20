use std::{collections::HashSet, io::Write, path::Path, sync::Mutex};
#[cfg(windows)]
use std::{fs, path::PathBuf};
#[cfg(not(any(unix, windows)))]
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::PathBuf,
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
    authoritative_bytes: Option<Vec<u8>>,
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
    AfterDirectoryCreateBeforeRootSync,
    AfterReplaceBeforeDirectorySync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoStage {
    BeforePolicyOpen,
    AfterPolicyOpen,
    BeforeTempCreate,
    AfterTempSync,
    BeforeReplace,
    AfterReplace,
}

#[derive(Debug)]
struct InvalidPolicy;

static DRIVE_PREFIX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(^|[[:space:]=:('])(?:[a-z]:[/\\])").unwrap());
static UNSAFE_PATH_PREFIX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(^|[[:space:]=:('])(?:file://|//|/[A-Za-z0-9._-]|[a-z]:[^[:space:]]*)")
        .unwrap()
});
static CREDENTIAL_ASSIGNMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(?:password|passwd|pwd|secret|api(?:[ _-]?key)|access(?:[ _-]?key)|auth(?:[ _-]?token)|client(?:[ _-]?secret)|private(?:[ _-]?key)|token|credential)\b[[:space:]]*[:=][[:space:]]*["']?[A-Za-z0-9_+./=-]{4,}"#,
    )
    .unwrap()
});
static AUTHORIZATION_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bauthorization\s*:\s*(?:basic|bearer)\s+[^[:space:]]+").unwrap()
});
static KNOWN_CREDENTIAL_PREFIX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,})",
    )
    .unwrap()
});
static TOKEN_CANDIDATE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9_+/=.-]{24,}").unwrap());
static POLICY_UPDATE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub fn load_policy(project_root: impl AsRef<Path>) -> Result<LoadedPolicy, CommandError> {
    load_policy_with_hook(project_root.as_ref(), |_| {})
}

#[cfg(test)]
fn load_policy_with_test_hook(
    project_root: &Path,
    hook: impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    load_policy_with_hook(project_root, hook)
}

#[cfg(unix)]
fn load_policy_with_hook(
    project_root: &Path,
    mut hook: impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    let (_, policy_dir, _) = match unix_fs::open_project_policy_dir(project_root, false) {
        Ok(handles) => handles,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(missing_policy()),
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    hook(IoStage::BeforePolicyOpen);
    let mut policy = match unix_fs::open_regular_at(&policy_dir, "policy.json", true) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(missing_policy()),
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    hook(IoStage::AfterPolicyOpen);
    let bytes = match unix_fs::read_bounded(&mut policy, MAX_POLICY_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    loaded_from_bytes(&bytes)
}

#[cfg(windows)]
fn load_policy_with_hook(
    project_root: &Path,
    mut hook: impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    let policy_dir = project_root.join(".oxaudit");
    if windows_fs::open_directory(&policy_dir).is_err() {
        return if policy_dir.exists() {
            Ok(invalid_loaded_policy())
        } else {
            Ok(missing_policy())
        };
    }
    hook(IoStage::BeforePolicyOpen);
    let mut policy = match windows_fs::open_regular(&policy_dir.join("policy.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(missing_policy()),
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    hook(IoStage::AfterPolicyOpen);
    let bytes = match windows_fs::read_bounded(&mut policy, MAX_POLICY_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    loaded_from_bytes(&bytes)
}

#[cfg(not(any(unix, windows)))]
fn load_policy_with_hook(
    project_root: &Path,
    mut hook: impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
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

    hook(IoStage::BeforePolicyOpen);
    let mut policy = match OpenOptions::new().read(true).open(&policy_path) {
        Ok(file) => file,
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    hook(IoStage::AfterPolicyOpen);
    let mut bytes = Vec::new();
    let read = policy.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_POLICY_BYTES {
        return Ok(invalid_loaded_policy());
    }
    loaded_from_bytes(&bytes)
}

fn loaded_from_bytes(bytes: &[u8]) -> Result<LoadedPolicy, CommandError> {
    match parse_and_validate(bytes, ValidationMode::Load) {
        Ok(policy) => {
            let hash = hash_bytes(bytes);
            Ok(LoadedPolicy {
                status: PolicyStatus::Valid { hash },
                policy: Some(policy),
                authoritative_bytes: Some(bytes.to_vec()),
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
    update_policy_decision_core(
        project_root.as_ref(),
        finding,
        request,
        now,
        WriteFailure::Never,
        |_| {},
    )
}

#[cfg(test)]
fn update_policy_decision_with_hook(
    project_root: impl AsRef<Path>,
    finding: &Finding,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    failure: WriteFailure,
) -> Result<ReviewRecord, CommandError> {
    update_policy_decision_core(
        project_root.as_ref(),
        finding,
        request,
        now,
        failure,
        |_| {},
    )
}

#[cfg(test)]
fn update_policy_decision_with_test_hook(
    project_root: &Path,
    finding: &Finding,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    failure: WriteFailure,
    hook: impl FnMut(IoStage),
) -> Result<ReviewRecord, CommandError> {
    update_policy_decision_core(project_root, finding, request, now, failure, hook)
}

fn update_policy_decision_core(
    project_root: &Path,
    finding: &Finding,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    failure: WriteFailure,
    mut hook: impl FnMut(IoStage),
) -> Result<ReviewRecord, CommandError> {
    let _update_guard = POLICY_UPDATE_LOCK
        .lock()
        .map_err(|_| CommandError::policy_write_failed())?;
    validate_update_input(finding, request, &now).map_err(|_| CommandError::review_invalid())?;

    let loaded = load_policy(project_root)?;
    let initial_bytes = loaded.authoritative_bytes.clone();
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
    atomic_write_policy(
        project_root,
        &bytes,
        initial_bytes.as_deref(),
        failure,
        &mut hook,
    )?;

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
    let raw = parse_json_without_duplicates(bytes)?;
    validate_closed_schema(&raw)?;
    let policy: PolicyFile = serde_json::from_value(raw).map_err(|_| InvalidPolicy)?;
    validate_policy(&policy, mode)?;
    Ok(policy)
}

fn parse_json_without_duplicates(bytes: &[u8]) -> Result<serde_json::Value, InvalidPolicy> {
    use serde::de::DeserializeSeed;

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJsonValue
        .deserialize(&mut deserializer)
        .map_err(|_| InvalidPolicy)?;
    deserializer.end().map_err(|_| InvalidPolicy)?;
    Ok(value)
}

struct UniqueJsonValue;

impl<'de> serde::de::DeserializeSeed<'de> for UniqueJsonValue {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueJsonVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueJsonValue)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            values.insert(key, map.next_value_seed(UniqueJsonValue)?);
        }
        Ok(serde_json::Value::Object(values))
    }
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
            if gates.is_empty() {
                return Err(InvalidPolicy);
            }
            let deciding_gate = deciding_gate.ok_or(InvalidPolicy)?;
            let mut seen = HashSet::new();
            let mut eliminating = 0;
            for note in gates {
                if !seen.insert(note.gate) || !safe_required_text(&note.evidence) {
                    return Err(InvalidPolicy);
                }
                if note.verdict == GateVerdict::Eliminates {
                    eliminating += 1;
                    if note.gate != deciding_gate {
                        return Err(InvalidPolicy);
                    }
                }
            }
            if eliminating != 1 {
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
    if DRIVE_PREFIX.is_match(value) || UNSAFE_PATH_PREFIX.is_match(value) {
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
        || (lower.contains("://") && lower.contains('@'))
        || CREDENTIAL_ASSIGNMENT.is_match(value)
        || AUTHORIZATION_VALUE.is_match(value)
        || KNOWN_CREDENTIAL_PREFIX.is_match(value)
    {
        return true;
    }
    TOKEN_CANDIDATE
        .find_iter(value)
        .map(|candidate| candidate.as_str())
        .any(high_entropy_standalone_token)
}

fn high_entropy_standalone_token(candidate: &str) -> bool {
    if candidate
        .chars()
        .all(|character| character.is_ascii_hexdigit())
        || benign_identifier(candidate)
        || portable_path_token(candidate)
    {
        return false;
    }
    let mut frequencies = [0usize; 128];
    for byte in candidate.bytes() {
        if byte.is_ascii() {
            frequencies[usize::from(byte)] += 1;
        }
    }
    let length = candidate.len() as f64;
    let entropy = frequencies
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    entropy >= 3.5
}

fn benign_identifier(candidate: &str) -> bool {
    let digit_start = candidate
        .find(|character: char| character.is_ascii_digit())
        .unwrap_or(candidate.len());
    let (name, suffix) = candidate.split_at(digit_start);
    if name.len() < 16
        || !name
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        || !suffix.chars().all(|character| character.is_ascii_digit())
    {
        return false;
    }
    let bytes = name.as_bytes();
    let uppercase = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| byte.is_ascii_uppercase())
        .count();
    uppercase > 0
        && uppercase <= name.len().div_ceil(6)
        && bytes.iter().enumerate().all(|(index, byte)| {
            !byte.is_ascii_uppercase()
                || ((index == 0 || bytes[index - 1].is_ascii_lowercase())
                    && (index + 1 == bytes.len() || bytes[index + 1].is_ascii_lowercase()))
        })
}

fn portable_path_token(candidate: &str) -> bool {
    let without_location = candidate
        .rsplit_once(':')
        .filter(|(_, suffix)| suffix.chars().all(|character| character.is_ascii_digit()))
        .map_or(candidate, |(path, _)| path);
    without_location.contains('/') && safe_relative_path(without_location)
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
        id: derived_review_id(project_id, policy_hash, fingerprint_version, fingerprint),
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
        id: derived_review_id(project_id, policy_hash, fingerprint_version, fingerprint),
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

fn derived_review_id(
    project_id: &str,
    policy_hash: Option<&str>,
    fingerprint_version: u16,
    fingerprint: &str,
) -> String {
    let version = fingerprint_version.to_string();
    let fields = [
        project_id,
        policy_hash.unwrap_or("missing"),
        version.as_str(),
        fingerprint,
    ];
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("project-policy:{:x}", digest.finalize())
}

#[cfg(unix)]
fn atomic_write_policy(
    project_root: &Path,
    bytes: &[u8],
    expected_bytes: Option<&[u8]>,
    failure: WriteFailure,
    hook: &mut impl FnMut(IoStage),
) -> Result<(), CommandError> {
    let (root, policy_dir, created) = unix_fs::open_project_policy_dir(project_root, true)
        .map_err(|_| CommandError::policy_write_failed())?;
    if created {
        if failure == WriteFailure::AfterDirectoryCreateBeforeRootSync {
            return Err(CommandError::policy_write_failed());
        }
        root.sync_all()
            .map_err(|_| CommandError::policy_write_failed())?;
    }
    let directory_identity =
        unix_fs::identity(&policy_dir).map_err(|_| CommandError::policy_write_failed())?;
    hook(IoStage::BeforeTempCreate);
    if !unix_fs::same_named_identity(&root, ".oxaudit", directory_identity) {
        return Err(CommandError::policy_write_failed());
    }

    let temp_name = format!(".policy.json.{}.tmp", Uuid::new_v4());
    let mut temp = unix_fs::create_new_at(&policy_dir, &temp_name)
        .map_err(|_| CommandError::policy_write_failed())?;
    let temp_identity =
        unix_fs::identity(&temp).map_err(|_| CommandError::policy_write_failed())?;
    let mut temp_cleanup = unix_fs::OwnedName::new(&policy_dir, temp_name.clone(), temp_identity);
    temp.write_all(bytes)
        .and_then(|_| temp.flush())
        .and_then(|_| temp.sync_all())
        .map_err(|_| CommandError::policy_write_failed())?;
    hook(IoStage::AfterTempSync);
    if failure == WriteFailure::AfterTempSync {
        return Err(CommandError::policy_write_failed());
    }
    if !unix_fs::same_named_identity(&root, ".oxaudit", directory_identity)
        || !unix_fs::same_named_identity(&policy_dir, &temp_name, temp_identity)
    {
        return Err(CommandError::policy_write_failed());
    }
    let persisted = unix_fs::read_bounded(&mut temp, MAX_POLICY_BYTES)
        .map_err(|_| CommandError::policy_write_failed())?;
    parse_and_validate(&persisted, ValidationMode::Load)
        .map_err(|_| CommandError::policy_write_failed())?;
    if persisted != bytes {
        return Err(CommandError::policy_write_failed());
    }

    hook(IoStage::BeforeReplace);
    if !unix_fs::same_named_identity(&root, ".oxaudit", directory_identity) {
        return Err(CommandError::policy_write_failed());
    }
    let current = match unix_fs::open_regular_at(&policy_dir, "policy.json", true) {
        Ok(mut file) => Some((
            unix_fs::read_bounded(&mut file, MAX_POLICY_BYTES)
                .map_err(|_| CommandError::policy_write_failed())?,
            unix_fs::identity(&file).map_err(|_| CommandError::policy_write_failed())?,
        )),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
        Err(_) => return Err(CommandError::policy_write_failed()),
    };
    let current_matches = match (expected_bytes, &current) {
        (None, None) => true,
        (Some(expected), Some((actual, _))) => expected == actual,
        _ => false,
    };
    if !current_matches {
        return Err(CommandError::policy_write_failed());
    }

    let backup_name = format!(".policy.json.{}.recovery", Uuid::new_v4());
    let mut backup = if let Some((_, current_identity)) = current {
        unix_fs::link_at(&policy_dir, "policy.json", &backup_name)
            .map_err(|_| CommandError::policy_write_failed())?;
        let backup_identity = unix_fs::named_identity(&policy_dir, &backup_name)
            .map_err(|_| CommandError::policy_write_failed())?;
        if backup_identity != current_identity
            || !unix_fs::same_named_identity(&policy_dir, "policy.json", current_identity)
        {
            let _ = unix_fs::unlink_at(&policy_dir, &backup_name);
            return Err(CommandError::policy_write_failed());
        }
        Some(unix_fs::OwnedName::new(
            &policy_dir,
            backup_name.clone(),
            backup_identity,
        ))
    } else {
        None
    };

    if !unix_fs::same_named_identity(&policy_dir, &temp_name, temp_identity) {
        return Err(CommandError::policy_write_failed());
    }
    unix_fs::rename_at(&policy_dir, &temp_name, "policy.json")
        .map_err(|_| CommandError::policy_write_failed())?;
    temp_cleanup.disarm();
    let rollback = |backup: &mut Option<unix_fs::OwnedName<'_>>| -> std::io::Result<()> {
        if let Some(backup) = backup.as_mut() {
            backup.restore_over("policy.json")?;
        } else if unix_fs::same_named_identity(&policy_dir, "policy.json", temp_identity) {
            unix_fs::unlink_at(&policy_dir, "policy.json")?;
        } else {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        policy_dir.sync_all()
    };
    if !unix_fs::same_named_identity(&root, ".oxaudit", directory_identity)
        || !unix_fs::same_named_identity(&policy_dir, "policy.json", temp_identity)
    {
        let _ = rollback(&mut backup);
        return Err(CommandError::policy_write_failed());
    }
    hook(IoStage::AfterReplace);

    if failure == WriteFailure::AfterReplaceBeforeDirectorySync
        || !unix_fs::same_named_identity(&policy_dir, "policy.json", temp_identity)
    {
        let _ = rollback(&mut backup);
        return Err(CommandError::policy_write_failed());
    }

    if policy_dir.sync_all().is_err() {
        let _ = rollback(&mut backup);
        return Err(CommandError::policy_write_failed());
    }
    if let Some(backup) = backup.as_mut() {
        let _ = backup.remove().and_then(|_| policy_dir.sync_all());
    }
    Ok(())
}

#[cfg(windows)]
fn atomic_write_policy(
    project_root: &Path,
    bytes: &[u8],
    expected_bytes: Option<&[u8]>,
    failure: WriteFailure,
    hook: &mut impl FnMut(IoStage),
) -> Result<(), CommandError> {
    let policy_dir = project_root.join(".oxaudit");
    let created = if policy_dir.exists() {
        false
    } else {
        fs::create_dir(&policy_dir).map_err(|_| CommandError::policy_write_failed())?;
        true
    };
    let directory =
        windows_fs::open_directory(&policy_dir).map_err(|_| CommandError::policy_write_failed())?;
    let directory_identity =
        windows_fs::identity(&directory).map_err(|_| CommandError::policy_write_failed())?;
    if created {
        if failure == WriteFailure::AfterDirectoryCreateBeforeRootSync {
            return Err(CommandError::policy_write_failed());
        }
        windows_fs::open_directory(project_root)
            .and_then(|root| root.sync_all())
            .map_err(|_| CommandError::policy_write_failed())?;
    }
    hook(IoStage::BeforeTempCreate);
    if !windows_fs::path_has_identity(&policy_dir, directory_identity, true) {
        return Err(CommandError::policy_write_failed());
    }

    let temp_path = policy_dir.join(format!(".policy.json.{}.tmp", Uuid::new_v4()));
    let mut temp =
        windows_fs::create_new(&temp_path).map_err(|_| CommandError::policy_write_failed())?;
    let temp_identity =
        windows_fs::identity(&temp).map_err(|_| CommandError::policy_write_failed())?;
    let mut cleanup = WindowsOwnedPath::new(temp_path.clone(), temp_identity);
    temp.write_all(bytes)
        .and_then(|_| temp.flush())
        .and_then(|_| temp.sync_all())
        .map_err(|_| CommandError::policy_write_failed())?;
    hook(IoStage::AfterTempSync);
    if failure == WriteFailure::AfterTempSync
        || !windows_fs::path_has_identity(&temp_path, temp_identity, false)
        || !windows_fs::path_has_identity(&policy_dir, directory_identity, true)
    {
        return Err(CommandError::policy_write_failed());
    }
    let persisted = windows_fs::read_bounded(&mut temp, MAX_POLICY_BYTES)
        .map_err(|_| CommandError::policy_write_failed())?;
    if persisted != bytes || parse_and_validate(&persisted, ValidationMode::Load).is_err() {
        return Err(CommandError::policy_write_failed());
    }

    hook(IoStage::BeforeReplace);
    let policy_path = policy_dir.join("policy.json");
    let current = match windows_fs::open_regular(&policy_path) {
        Ok(mut file) => Some(
            windows_fs::read_bounded(&mut file, MAX_POLICY_BYTES)
                .map_err(|_| CommandError::policy_write_failed())?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(CommandError::policy_write_failed()),
    };
    if current.as_deref() != expected_bytes
        || !windows_fs::path_has_identity(&policy_dir, directory_identity, true)
        || !windows_fs::path_has_identity(&temp_path, temp_identity, false)
    {
        return Err(CommandError::policy_write_failed());
    }

    let backup_path = policy_dir.join(format!(".policy.json.{}.recovery", Uuid::new_v4()));
    let had_policy = current.is_some();
    windows_fs::durable_replace(
        &policy_path,
        &temp_path,
        had_policy,
        had_policy.then_some(backup_path.as_path()),
    )
    .map_err(|_| CommandError::policy_write_failed())?;
    cleanup.disarm();
    let mut backup = if had_policy {
        let backup_file = windows_fs::open_regular(&backup_path)
            .map_err(|_| CommandError::policy_write_failed())?;
        let backup_identity =
            windows_fs::identity(&backup_file).map_err(|_| CommandError::policy_write_failed())?;
        Some(WindowsOwnedPath::new(backup_path.clone(), backup_identity))
    } else {
        None
    };
    let rollback = |backup: &mut Option<WindowsOwnedPath>| -> std::io::Result<()> {
        if let Some(backup) = backup.as_mut() {
            backup.restore_over(&policy_path)?;
        } else if windows_fs::path_has_identity(&policy_path, temp_identity, false) {
            fs::remove_file(&policy_path)?;
        } else {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        directory.sync_all()
    };
    if !windows_fs::path_has_identity(&policy_dir, directory_identity, true)
        || !windows_fs::path_has_identity(&policy_path, temp_identity, false)
    {
        let _ = rollback(&mut backup);
        return Err(CommandError::policy_write_failed());
    }
    hook(IoStage::AfterReplace);
    if failure == WriteFailure::AfterReplaceBeforeDirectorySync
        || !windows_fs::path_has_identity(&policy_path, temp_identity, false)
    {
        let _ = rollback(&mut backup);
        return Err(CommandError::policy_write_failed());
    }
    if directory.sync_all().is_err() {
        let _ = rollback(&mut backup);
        return Err(CommandError::policy_write_failed());
    }
    if let Some(backup) = backup.as_mut() {
        let _ = backup.remove().and_then(|_| directory.sync_all());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn atomic_write_policy(
    project_root: &Path,
    bytes: &[u8],
    expected_bytes: Option<&[u8]>,
    failure: WriteFailure,
    hook: &mut impl FnMut(IoStage),
) -> Result<(), CommandError> {
    let policy_dir = project_root.join(".oxaudit");
    ensure_real_policy_directory(&policy_dir)?;
    let policy_path = policy_dir.join("policy.json");
    ensure_regular_or_missing(&policy_path)?;
    let current = fs::read(&policy_path).ok();
    if current.as_deref() != expected_bytes {
        return Err(CommandError::policy_write_failed());
    }
    hook(IoStage::BeforeTempCreate);
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
    hook(IoStage::AfterTempSync);
    if failure == WriteFailure::AfterTempSync {
        return Err(CommandError::policy_write_failed());
    }
    let mut persisted = Vec::new();
    File::open(&temp_path)
        .and_then(|file| file.take(MAX_POLICY_BYTES + 1).read_to_end(&mut persisted))
        .map_err(|_| CommandError::policy_write_failed())?;
    if persisted != bytes || parse_and_validate(&persisted, ValidationMode::Load).is_err() {
        return Err(CommandError::policy_write_failed());
    }
    hook(IoStage::BeforeReplace);
    if fs::read(&policy_path).ok().as_deref() != expected_bytes {
        return Err(CommandError::policy_write_failed());
    }
    fs::rename(&temp_path, &policy_path).map_err(|_| CommandError::policy_write_failed())?;
    cleanup.committed = true;
    hook(IoStage::AfterReplace);
    if failure == WriteFailure::AfterReplaceBeforeDirectorySync {
        return Err(CommandError::policy_write_failed());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
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

#[cfg(not(any(unix, windows)))]
fn ensure_regular_or_missing(path: &Path) -> Result<(), CommandError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(CommandError::policy_write_failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CommandError::policy_write_failed()),
    }
}

#[cfg(not(any(unix, windows)))]
struct OwnedTemp {
    path: PathBuf,
    committed: bool,
}

#[cfg(not(any(unix, windows)))]
impl OwnedTemp {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }
}

#[cfg(not(any(unix, windows)))]
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
        authoritative_bytes: None,
    }
}

fn invalid_loaded_policy() -> LoadedPolicy {
    LoadedPolicy {
        status: PolicyStatus::Invalid {
            message: INVALID_POLICY_MESSAGE.to_owned(),
        },
        policy: None,
        authoritative_bytes: None,
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn timestamp(now: &DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(windows)]
mod windows_fs {
    use std::{
        ffi::OsStr,
        fs::{File, OpenOptions},
        io::{self, Read, Seek, SeekFrom},
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::Path,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, MoveFileExW, ReplaceFileW, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Identity {
        volume: u32,
        index: u64,
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn shared_options() -> OpenOptions {
        let mut options = OpenOptions::new();
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        options
    }

    fn reject_reparse(file: File) -> io::Result<File> {
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            Err(io::Error::from_raw_os_error(4390))
        } else {
            Ok(file)
        }
    }

    pub(super) fn open_directory(path: &Path) -> io::Result<File> {
        let mut options = shared_options();
        options
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let file = reject_reparse(options.open(path)?)?;
        if file.metadata()?.is_dir() {
            Ok(file)
        } else {
            Err(io::Error::from_raw_os_error(267))
        }
    }

    pub(super) fn open_regular(path: &Path) -> io::Result<File> {
        let mut options = shared_options();
        options
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = reject_reparse(options.open(path)?)?;
        if file.metadata()?.is_file() {
            Ok(file)
        } else {
            Err(io::Error::from_raw_os_error(87))
        }
    }

    pub(super) fn create_new(path: &Path) -> io::Result<File> {
        let mut options = shared_options();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        reject_reparse(options.open(path)?)
    }

    pub(super) fn read_bounded(file: &mut File, max: u64) -> io::Result<Vec<u8>> {
        if !file.metadata()?.is_file() {
            return Err(io::Error::from_raw_os_error(87));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(max + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max {
            Err(io::Error::from_raw_os_error(223))
        } else {
            Ok(bytes)
        }
    }

    pub(super) fn identity(file: &File) -> io::Result<Identity> {
        let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        let ok =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let information = unsafe { information.assume_init() };
        Ok(Identity {
            volume: information.dwVolumeSerialNumber,
            index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }

    pub(super) fn path_has_identity(path: &Path, expected: Identity, directory: bool) -> bool {
        let opened = if directory {
            open_directory(path)
        } else {
            open_regular(path)
        };
        opened
            .and_then(|file| identity(&file))
            .is_ok_and(|actual| actual == expected)
    }

    /// Uses the Win32 durable replacement primitives. Existing targets use
    /// ReplaceFileW, optionally creating an attempt-owned recovery backup;
    /// initially missing targets use MoveFileExW with write-through.
    pub(super) fn durable_replace(
        target: &Path,
        replacement: &Path,
        target_exists: bool,
        backup: Option<&Path>,
    ) -> io::Result<()> {
        let target = wide(target);
        let replacement = wide(replacement);
        let backup = backup.map(wide);
        let ok = if target_exists {
            unsafe {
                ReplaceFileW(
                    target.as_ptr(),
                    replacement.as_ptr(),
                    backup
                        .as_ref()
                        .map_or(std::ptr::null(), |path| path.as_ptr()),
                    REPLACEFILE_WRITE_THROUGH,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            }
        } else {
            unsafe {
                MoveFileExW(
                    replacement.as_ptr(),
                    target.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            }
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn _wide_os_str(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(windows)]
struct WindowsOwnedPath {
    path: PathBuf,
    identity: windows_fs::Identity,
    armed: bool,
}

#[cfg(windows)]
impl WindowsOwnedPath {
    fn new(path: PathBuf, identity: windows_fs::Identity) -> Self {
        Self {
            path,
            identity,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn remove(&mut self) -> std::io::Result<()> {
        if self.armed && windows_fs::path_has_identity(&self.path, self.identity, false) {
            fs::remove_file(&self.path)?;
        }
        self.armed = false;
        Ok(())
    }

    fn restore_over(&mut self, target: &Path) -> std::io::Result<()> {
        if !self.armed || !windows_fs::path_has_identity(&self.path, self.identity, false) {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        windows_fs::durable_replace(target, &self.path, true, None)?;
        self.disarm();
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsOwnedPath {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(unix)]
mod unix_fs {
    use std::{
        ffi::CString,
        fs::File,
        io::{self, Read, Seek, SeekFrom},
        os::{fd::AsRawFd, unix::ffi::OsStrExt, unix::io::FromRawFd},
        path::Path,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Identity {
        pub(super) device: libc::dev_t,
        pub(super) inode: libc::ino_t,
    }

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    fn c_name(name: &str) -> io::Result<CString> {
        CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    /// Opens a directory without following the final path component. The
    /// returned `File` owns the descriptor and pins every subsequent `openat`
    /// operation to this inode even if a pathname is concurrently swapped.
    fn open_directory(path: &Path) -> io::Result<File> {
        let path = c_path(path)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn open_project_policy_dir(
        project_root: &Path,
        create: bool,
    ) -> io::Result<(File, File, bool)> {
        let canonical = project_root.canonicalize()?;
        let root = open_directory(&canonical)?;
        let name = c_name(".oxaudit")?;
        let mut fd = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        let mut created = false;
        if fd < 0 && create && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
            created = true;
            fd = unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((root, unsafe { File::from_raw_fd(fd) }, created))
    }

    pub(super) fn open_regular_at(
        directory: &File,
        name: &str,
        nonblocking: bool,
    ) -> io::Result<File> {
        let name = c_name(name)?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if nonblocking { libc::O_NONBLOCK } else { 0 };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        require_regular(&file)?;
        Ok(file)
    }

    pub(super) fn create_new_at(directory: &File, name: &str) -> io::Result<File> {
        let name = c_name(name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn read_bounded(file: &mut File, max: u64) -> io::Result<Vec<u8>> {
        require_regular(file)?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(max + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max {
            Err(io::Error::from_raw_os_error(libc::EFBIG))
        } else {
            Ok(bytes)
        }
    }

    pub(super) fn identity(file: &File) -> io::Result<Identity> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(Identity {
            device: stat.st_dev,
            inode: stat.st_ino,
        })
    }

    pub(super) fn named_identity(directory: &File, name: &str) -> io::Result<Identity> {
        let name = c_name(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(Identity {
            device: stat.st_dev,
            inode: stat.st_ino,
        })
    }

    fn require_regular(file: &File) -> io::Result<()> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT == libc::S_IFREG {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }
    }

    pub(super) fn link_at(directory: &File, from: &str, to: &str) -> io::Result<()> {
        let from = c_name(from)?;
        let to = c_name(to)?;
        if unsafe {
            libc::linkat(
                directory.as_raw_fd(),
                from.as_ptr(),
                directory.as_raw_fd(),
                to.as_ptr(),
                0,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn rename_at(directory: &File, from: &str, to: &str) -> io::Result<()> {
        let from = c_name(from)?;
        let to = c_name(to)?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                from.as_ptr(),
                directory.as_raw_fd(),
                to.as_ptr(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn unlink_at(directory: &File, name: &str) -> io::Result<()> {
        let name = c_name(name)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn same_named_identity(directory: &File, name: &str, expected: Identity) -> bool {
        named_identity(directory, name).is_ok_and(|actual| actual == expected)
    }

    pub(super) struct OwnedName<'a> {
        directory: &'a File,
        name: String,
        identity: Identity,
        armed: bool,
    }

    impl<'a> OwnedName<'a> {
        pub(super) fn new(directory: &'a File, name: String, identity: Identity) -> Self {
            Self {
                directory,
                name,
                identity,
                armed: true,
            }
        }

        pub(super) fn disarm(&mut self) {
            self.armed = false;
        }

        pub(super) fn remove(&mut self) -> io::Result<()> {
            if self.armed && same_named_identity(self.directory, &self.name, self.identity) {
                unlink_at(self.directory, &self.name)?;
            }
            self.armed = false;
            Ok(())
        }

        pub(super) fn restore_over(&mut self, target: &str) -> io::Result<()> {
            if !self.armed || !same_named_identity(self.directory, &self.name, self.identity) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            rename_at(self.directory, &self.name, target)?;
            self.disarm();
            Ok(())
        }
    }

    impl Drop for OwnedName<'_> {
        fn drop(&mut self) {
            let _ = self.remove();
        }
    }
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
    fn duplicate_json_keys_are_rejected_at_every_object_depth() {
        let duplicates = [
            r#"{"version":999,"version":1,"entries":[]}"#,
            r#"{"version":1,"entries":[{"kind":"unknown","kind":"suppression","ruleId":"rule","pathPattern":"tests/**","state":"suppressed","reason":"Fixture"}]}"#,
            r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"rule","pathPattern":"tests/**","state":"acceptedRisk","state":"suppressed","reason":"Fixture"}]}"#,
            r#"{"version":1,"entries":[{"kind":"finding","fingerprintVersion":1,"fingerprint":"abc123","category":"vulnerability","category":"secret","state":"acceptedRisk","reason":"Fixture"}]}"#,
            r#"{"version":1,"entries":[{"kind":"finding","fingerprintVersion":1,"fingerprint":"abc123","category":"vulnerability","state":"falsePositive","reason":"Fixture","gates":[{"gate":"reachable","verdict":"survives","verdict":"eliminates","evidence":"Excluded"}],"decidingGate":"reachable"}]}"#,
        ];
        for (index, bytes) in duplicates.into_iter().enumerate() {
            let root = tempfile::tempdir().unwrap();
            write_policy(root.path(), bytes.as_bytes());
            assert!(
                matches!(
                    load_policy(root.path()).unwrap().status(),
                    PolicyStatus::Invalid { .. }
                ),
                "accepted duplicate-key fixture {index}"
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
    fn structured_credential_forms_are_rejected_without_echoing_them() {
        let rejected = [
            "password = huntertwo",
            "api key: abcdefghijklmnop",
            "api_key = ABCDEFGHIJKLMNOP",
            "token : Zm9vYmFyYmF6cXV4",
            "Authorization: Basic YWJj",
            "Authorization: Bearer tiny-token",
            "-----BEGIN PRIVATE KEY-----",
            "AWS key AKIAIOSFODNN7EXAMPLE",
            "GitHub token ghp_abcdefghijklmnopqrstuvwxyz012345",
            "OpenAI key sk-abcdefghijklmnopqrstuvwxyz",
        ];
        for (index, value) in rejected.into_iter().enumerate() {
            assert!(
                !safe_required_text(value),
                "accepted credential-shaped fixture {index}"
            );
        }
    }

    #[test]
    fn absolute_unc_uri_drive_and_traversal_path_tokens_are_rejected() {
        for value in [
            "path=//server/share",
            "file:///Users/alice/private.rs",
            "source=C:/private/source.rs",
            "source=C:private/source.rs",
            "checked /etc/passwd",
            "checked src/../../private.rs",
        ] {
            assert!(
                !safe_required_text(value),
                "accepted unsafe path-shaped input"
            );
        }
    }

    #[test]
    fn benign_hash_identifiers_and_relative_paths_remain_portable() {
        for value in [
            "commit 0123456789abcdef0123456789abcdef01234567",
            "identifier ExtremelyLongApplicationSecurityIdentifier2026",
            "reviewed at src/security/policy.rs:42",
            "manifest fixtures/example-project/config.json",
        ] {
            assert!(
                safe_required_text(value),
                "rejected benign portable input: {value}"
            );
        }
    }

    #[test]
    fn standalone_high_entropy_tokens_are_rejected() {
        for value in [
            "n7Qv2Lm9Rx4Za8Wp3Kd6Ty1Bc5Hf0JsU",
            "VGhpcy1pcy1ub3QtYS1yZWFsLXNlY3JldA==",
        ] {
            assert!(!safe_required_text(value));
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
    fn derived_review_ids_include_project_and_authoritative_policy_hash() {
        let first_root = tempfile::tempdir().unwrap();
        write_policy(first_root.path(), VALID_POLICY.as_bytes());
        let first = load_policy(first_root.path()).unwrap();
        let project_one = apply_policy(
            &first,
            "project-1",
            1,
            "abc123",
            "vulnerability",
            "rule",
            "src/a.rs",
            None,
            now(),
        )
        .unwrap();
        let project_two = apply_policy(
            &first,
            "project-2",
            1,
            "abc123",
            "vulnerability",
            "rule",
            "src/a.rs",
            None,
            now(),
        )
        .unwrap();
        assert_ne!(project_one.id, project_two.id);

        let second_root = tempfile::tempdir().unwrap();
        let changed = VALID_POLICY.replace(
            "The affected branch is excluded from production",
            "The deployment manifest excludes this branch",
        );
        write_policy(second_root.path(), changed.as_bytes());
        let second = load_policy(second_root.path()).unwrap();
        let changed_review = apply_policy(
            &second,
            "project-1",
            1,
            "abc123",
            "vulnerability",
            "rule",
            "src/a.rs",
            None,
            now(),
        )
        .unwrap();
        assert_ne!(project_one.id, changed_review.id);
        assert_eq!(
            project_one.id,
            apply_policy(
                &first,
                "project-1",
                1,
                "abc123",
                "vulnerability",
                "rule",
                "src/a.rs",
                None,
                now(),
            )
            .unwrap()
            .id
        );
    }

    #[test]
    fn candidate_review_ids_do_not_collide_across_projects() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let loaded = load_policy(root.path()).unwrap();
        let one = apply_policy(
            &loaded,
            "project-1",
            1,
            "abc123",
            "secret",
            "rule",
            "src/a.rs",
            None,
            now(),
        )
        .unwrap();
        let two = apply_policy(
            &loaded,
            "project-2",
            1,
            "abc123",
            "secret",
            "rule",
            "src/a.rs",
            None,
            now(),
        )
        .unwrap();
        assert_ne!(one.id, two.id);
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
    fn vulnerability_false_positive_preserves_unique_multi_gate_investigation() {
        let root = tempfile::tempdir().unwrap();
        let gates = vec![
            GateNote {
                gate: Gate::Intended,
                verdict: GateVerdict::Survives,
                evidence: "The behavior is not intended".into(),
            },
            GateNote {
                gate: Gate::Reachable,
                verdict: GateVerdict::Eliminates,
                evidence: "The production manifest excludes src/dev.rs:8".into(),
            },
            GateNote {
                gate: Gate::AttackerControlled,
                verdict: GateVerdict::Unknown,
                evidence: "Not evaluated after elimination".into(),
            },
        ];
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "vulnerability", "state": "falsePositive", "reason": "Unreachable",
                "gates": gates, "decidingGate": "reachable"
            }]}),
        );
        assert!(matches!(loaded.status(), PolicyStatus::Valid { .. }));
        let review = apply(&loaded, "abc123", "vulnerability", "rule", "src/a.rs", None).unwrap();
        assert_eq!(review.gates, gates);
    }

    #[test]
    fn vulnerability_false_positive_rejects_duplicate_or_multiple_eliminating_gates() {
        let invalid_gate_sets = [
            serde_json::json!([
                {"gate":"reachable","verdict":"survives","evidence":"Checked"},
                {"gate":"reachable","verdict":"eliminates","evidence":"Excluded"}
            ]),
            serde_json::json!([
                {"gate":"intended","verdict":"eliminates","evidence":"Designed"},
                {"gate":"reachable","verdict":"eliminates","evidence":"Excluded"}
            ]),
            serde_json::json!([
                {"gate":"intended","verdict":"survives","evidence":"   "},
                {"gate":"reachable","verdict":"eliminates","evidence":"Excluded"}
            ]),
        ];
        for gates in invalid_gate_sets {
            let root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                root.path(),
                serde_json::json!({"version":1,"entries":[{
                    "kind":"finding","fingerprintVersion":1,"fingerprint":"abc123",
                    "category":"vulnerability","state":"falsePositive","reason":"Excluded",
                    "gates":gates,"decidingGate":"reachable"
                }]}),
            );
            assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
        }
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

    #[cfg(unix)]
    #[test]
    fn policy_open_does_not_block_when_a_checked_target_becomes_a_fifo() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), VALID_POLICY.as_bytes());
        let policy_path = root.path().join(".oxaudit/policy.json");

        let loaded = load_policy_with_test_hook(root.path(), |stage| {
            if stage == IoStage::BeforePolicyOpen {
                fs::remove_file(&policy_path).unwrap();
                let path = CString::new(policy_path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        })
        .unwrap();

        assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn policy_read_is_bounded_from_the_open_handle_when_the_file_grows() {
        use std::io::Write as _;

        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), VALID_POLICY.as_bytes());
        let policy_path = root.path().join(".oxaudit/policy.json");

        let loaded = load_policy_with_test_hook(root.path(), |stage| {
            if stage == IoStage::AfterPolicyOpen {
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(&policy_path)
                    .unwrap();
                file.write_all(&vec![b'x'; MAX_POLICY_BYTES as usize + 1])
                    .unwrap();
            }
        })
        .unwrap();

        assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn policy_read_stays_on_the_open_inode_when_the_name_is_swapped() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), VALID_POLICY.as_bytes());
        let policy_path = root.path().join(".oxaudit/policy.json");
        let held_path = root.path().join(".oxaudit/original-policy");
        let outside = root.path().join("outside-policy");
        fs::write(&outside, br#"{"version":999,"secret":"outside"}"#).unwrap();
        let expected_hash = format!("{:x}", Sha256::digest(VALID_POLICY.as_bytes()));

        let loaded = load_policy_with_test_hook(root.path(), |stage| {
            if stage == IoStage::AfterPolicyOpen {
                fs::rename(&policy_path, &held_path).unwrap();
                symlink(&outside, &policy_path).unwrap();
            }
        })
        .unwrap();

        assert_eq!(status_hash(&loaded), Some(expected_hash.as_str()));
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_valid_or_invalid_policy_update_wins_without_being_overwritten() {
        for external in [
            br#"{ "version": 1, "entries": [] }
"#
            .as_slice(),
            br#"{"version":999,"external":"invalid-but-authoritative"}"#.as_slice(),
        ] {
            let root = tempfile::tempdir().unwrap();
            write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
            let policy_path = root.path().join(".oxaudit/policy.json");

            let error = update_policy_decision_with_test_hook(
                root.path(),
                &finding("secret"),
                &request(ReviewState::FalsePositive, "secret"),
                now(),
                WriteFailure::Never,
                |stage| {
                    if stage == IoStage::BeforeReplace {
                        fs::write(&policy_path, external).unwrap();
                    }
                },
            )
            .unwrap_err();

            assert_eq!(
                error.code,
                crate::findings::error::ErrorCode::PolicyWriteFailed
            );
            assert_eq!(fs::read(&policy_path).unwrap(), external);
        }
    }

    #[cfg(unix)]
    #[test]
    fn concurrently_created_policy_wins_when_the_initial_policy_was_missing() {
        let root = tempfile::tempdir().unwrap();
        let policy_path = root.path().join(".oxaudit/policy.json");
        let external = br#"{"version":999,"external":"created"}"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::BeforeReplace {
                    fs::write(&policy_path, external).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(policy_path).unwrap(), external);
    }

    #[cfg(unix)]
    #[test]
    fn swapped_policy_directory_and_temp_name_cannot_redirect_a_write() {
        use std::os::unix::fs::symlink;

        for swap_stage in [IoStage::BeforeTempCreate, IoStage::AfterTempSync] {
            let root = tempfile::tempdir().unwrap();
            write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
            let original = fs::read(root.path().join(".oxaudit/policy.json")).unwrap();
            let held = root.path().join(".oxaudit-held");
            let attacker = root.path().join("attacker");
            fs::create_dir(&attacker).unwrap();

            let error = update_policy_decision_with_test_hook(
                root.path(),
                &finding("secret"),
                &request(ReviewState::FalsePositive, "secret"),
                now(),
                WriteFailure::Never,
                |stage| {
                    if stage == swap_stage {
                        fs::rename(root.path().join(".oxaudit"), &held).unwrap();
                        symlink(&attacker, root.path().join(".oxaudit")).unwrap();
                    }
                },
            )
            .unwrap_err();

            assert_eq!(
                error.code,
                crate::findings::error::ErrorCode::PolicyWriteFailed
            );
            assert!(!attacker.join("policy.json").exists());
            assert_eq!(fs::read(held.join("policy.json")).unwrap(), original);
        }
    }

    #[cfg(unix)]
    #[test]
    fn swapped_attempt_owned_temp_name_cannot_redirect_or_remove_another_file() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let original = fs::read(&policy_path).unwrap();
        let outside = root.path().join("outside.json");
        fs::write(&outside, b"outside").unwrap();

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::AfterTempSync {
                    let temp_path = fs::read_dir(root.path().join(".oxaudit"))
                        .unwrap()
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .find(|path| {
                            path.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".policy.json.")
                                && path.extension().is_some_and(|value| value == "tmp")
                        })
                        .unwrap();
                    fs::rename(&temp_path, temp_path.with_extension("stolen")).unwrap();
                    symlink(&outside, &temp_path).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(policy_path).unwrap(), original);
        assert_eq!(fs::read(outside).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn swapped_final_policy_name_cannot_redirect_a_write() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let held = root.path().join(".oxaudit/policy-held");
        let outside = root.path().join("outside.json");
        fs::write(&outside, b"outside").unwrap();

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::BeforeReplace {
                    fs::rename(&policy_path, &held).unwrap();
                    symlink(&outside, &policy_path).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(held).unwrap(), br#"{"version":1,"entries":[]}"#);
        assert_eq!(fs::read(outside).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn post_replace_sync_failure_restores_prior_or_missing_policy_exactly() {
        for had_policy in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let original = br#"{"version":1,"entries":[]}"#;
            if had_policy {
                write_policy(root.path(), original);
            }

            let error = update_policy_decision_with_test_hook(
                root.path(),
                &finding("secret"),
                &request(ReviewState::FalsePositive, "secret"),
                now(),
                WriteFailure::AfterReplaceBeforeDirectorySync,
                |_| {},
            )
            .unwrap_err();
            assert_eq!(
                error.code,
                crate::findings::error::ErrorCode::PolicyWriteFailed
            );

            let policy_path = root.path().join(".oxaudit/policy.json");
            if had_policy {
                assert_eq!(fs::read(policy_path).unwrap(), original);
            } else {
                assert!(!policy_path.exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_new_directory_root_sync_never_reports_a_policy_write() {
        let root = tempfile::tempdir().unwrap();
        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterDirectoryCreateBeforeRootSync,
            |_| {},
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert!(!root.path().join(".oxaudit/policy.json").exists());
    }
}
