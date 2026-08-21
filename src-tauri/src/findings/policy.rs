use std::{
    collections::HashSet,
    io::Write,
    ops::Range,
    path::Path,
    sync::{Mutex, MutexGuard},
};
#[cfg(windows)]
use std::{fs, path::PathBuf};
#[cfg(unix)]
use std::{fs::File, path::PathBuf};
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
enum PolicyWriteTerminal {
    CandidateDurablyCommitted,
    PriorOrNewerAuthoritative,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoStage {
    BeforePolicyOpen,
    AfterPolicyOpen,
    BeforeTempCreate,
    AfterTempSync,
    BeforeReplace,
    AfterPolicyPreflight,
    AfterReplace,
    BeforeRollbackExchange,
    AfterRollbackRecheckBeforeUndo,
}

#[derive(Debug)]
struct InvalidPolicy;

static CREDENTIAL_ASSIGNMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(?:password|passwd|pwd|secret|api(?:[ _-]?key)|access(?:[ _-]?key)|auth(?:[ _-]?token)|client(?:[ _-]?secret)|private(?:[ _-]?key)|token|credential)\b[[:space:]]*[:=][[:space:]]*["']?[^[:space:]"']+"#,
    )
    .unwrap()
});
static AUTHORIZATION_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:authorization\s*:\s*)?(?:basic|bearer)\s+[^[:space:]]+").unwrap()
});
static KNOWN_CREDENTIAL_PREFIX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)\b(?:AKIA[0-9A-Z]+|gh[pousr]_[A-Za-z0-9]+|sk-[A-Za-z0-9_-]+|xox[baprs]-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]+)",
    )
    .unwrap()
});
static TOKEN_CANDIDATE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9_+/=.-]{24,}").unwrap());
static POLICY_UPDATE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub(in crate::findings) struct PolicyAuthority<'a> {
    _guard: MutexGuard<'a, ()>,
}

pub(in crate::findings) fn with_policy_authority<T>(
    operation: impl FnOnce(&PolicyAuthority<'_>) -> Result<T, CommandError>,
) -> Result<T, CommandError> {
    let guard = POLICY_UPDATE_LOCK
        .lock()
        .map_err(|_| CommandError::policy_write_failed())?;
    operation(&PolicyAuthority { _guard: guard })
}

#[cfg(test)]
pub(crate) fn test_policy_authority_is_available() -> bool {
    POLICY_UPDATE_LOCK.try_lock().is_ok()
}

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
    hook: impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    let (_, policy_dir, _) = match unix_fs::open_project_policy_dir(project_root, false) {
        Ok(handles) => handles,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(missing_policy()),
        Err(_) => return Ok(invalid_loaded_policy()),
    };
    load_policy_from_unix_dir(&policy_dir, hook)
}

#[cfg(unix)]
fn load_policy_from_unix_dir(
    policy_dir: &File,
    mut hook: impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    hook(IoStage::BeforePolicyOpen);
    let mut policy = match unix_fs::open_regular_at(policy_dir, "policy.json", true) {
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

pub(crate) fn reproject_or_clear_orphaned_policy_review(
    loaded: &LoadedPolicy,
    current: &ReviewRecord,
    now: DateTime<Utc>,
) -> Result<ReviewRecord, CommandError> {
    if matches!(loaded.status(), PolicyStatus::Invalid { .. })
        || current.origin != ReviewOrigin::ProjectPolicy
    {
        return Err(CommandError::policy_invalid());
    }
    if current.policy_hash.as_deref() == loaded.hash() {
        return Ok(current.clone());
    }
    Ok(candidate_review(
        &current.project_id,
        current.fingerprint_version,
        &current.fingerprint,
        loaded.hash(),
        &now,
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
    with_policy_authority(|authority| {
        let reloaded = update_policy_decision_under_authority_with_hook(
            authority,
            project_root,
            finding,
            request,
            now,
            failure,
            &mut hook,
        )?;
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
    })
}

pub(in crate::findings) fn update_policy_decision_under_authority(
    authority: &PolicyAuthority<'_>,
    project_root: &Path,
    finding: &Finding,
    request: &ReviewRequest,
    now: DateTime<Utc>,
) -> Result<LoadedPolicy, CommandError> {
    update_policy_decision_under_authority_with_hook(
        authority,
        project_root,
        finding,
        request,
        now,
        WriteFailure::Never,
        &mut |_| {},
    )
}

fn update_policy_decision_under_authority_with_hook(
    _authority: &PolicyAuthority<'_>,
    project_root: &Path,
    finding: &Finding,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    failure: WriteFailure,
    hook: &mut impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    validate_update_input(finding, request, &now).map_err(|_| CommandError::review_invalid())?;

    let mut capability = open_update_capability(project_root, failure)?;
    let loaded = load_policy_for_update(&mut capability, &mut *hook)?;
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
    let terminal = atomic_write_policy(
        &mut capability,
        &bytes,
        initial_bytes.as_deref(),
        failure,
        &mut *hook,
    )?;
    if terminal != PolicyWriteTerminal::CandidateDurablyCommitted {
        return Err(CommandError::policy_write_failed());
    }

    let reloaded = load_policy_for_update(&mut capability, &mut |_| {})?;
    if !matches!(reloaded.status(), PolicyStatus::Valid { .. }) {
        return Err(CommandError::policy_write_failed());
    }
    Ok(reloaded)
}

pub(in crate::findings) fn load_policy_under_authority(
    _authority: &PolicyAuthority<'_>,
    project_root: &Path,
) -> Result<LoadedPolicy, CommandError> {
    load_policy(project_root)
}

pub(in crate::findings) fn policy_authority_still_matches(
    authority: &PolicyAuthority<'_>,
    project_root: &Path,
    expected: &LoadedPolicy,
) -> Result<bool, CommandError> {
    load_policy_under_authority(authority, project_root).map(|current| current == *expected)
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

pub(crate) fn validate_portable_review_fields(
    request: &ReviewRequest,
    now: &DateTime<Utc>,
) -> bool {
    if request.origin != ReviewOrigin::ProjectPolicy {
        return false;
    }
    if request.state == ReviewState::Candidate {
        return request.reason.trim().is_empty()
            && request.evidence.is_none()
            && request.entry_point.is_none()
            && request.data_flow.is_none()
            && request.gates.is_empty()
            && request.deciding_gate.is_none()
            && request.expires_at.is_none();
    }
    validate_finding_decision(
        &request.category,
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
    .is_ok()
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
                match note.verdict {
                    GateVerdict::Survives => {}
                    GateVerdict::Eliminates => {
                        eliminating += 1;
                        if note.gate != deciding_gate {
                            return Err(InvalidPolicy);
                        }
                    }
                    GateVerdict::Unknown => return Err(InvalidPolicy),
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
    let scan = scan_portable_text(value);
    let _ = scan.operations;
    !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !value.contains("[REDACTED]")
        && !scan.unsafe_path
        && !credential_shaped(value, &scan.safe_url_ranges)
}

#[derive(Debug)]
struct PortableTextScan {
    unsafe_path: bool,
    safe_url_ranges: Vec<Range<usize>>,
    operations: usize,
}

fn scan_portable_text(value: &str) -> PortableTextScan {
    let bytes = value.as_bytes();
    let mut safe_url_ranges = Vec::new();
    let mut operations = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        operations = operations.saturating_add(1);
        if starts_http_scheme(bytes, index) {
            match validate_http_url_at(bytes, index, &mut operations) {
                Ok(end) => {
                    safe_url_ranges.push(index..end);
                    index = end;
                    continue;
                }
                Err(()) => {
                    return PortableTextScan {
                        unsafe_path: true,
                        safe_url_ranges,
                        operations,
                    };
                }
            }
        }

        if path_candidate_byte(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && path_candidate_byte(bytes[index]) {
                operations = operations.saturating_add(1);
                index += 1;
            }
            let candidate = &value[start..index];
            if unsafe_path_candidate(candidate)
                || (candidate.len() == 1
                    && candidate.as_bytes()[0].is_ascii_alphabetic()
                    && bytes.get(index) == Some(&b':'))
            {
                return PortableTextScan {
                    unsafe_path: true,
                    safe_url_ranges,
                    operations,
                };
            }
        } else {
            index += 1;
        }
    }

    PortableTextScan {
        unsafe_path: false,
        safe_url_ranges,
        operations,
    }
}

#[cfg(test)]
fn portable_text_validation_work(value: &str) -> usize {
    scan_portable_text(value).operations
}

fn path_candidate_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
}

fn starts_http_scheme(bytes: &[u8], start: usize) -> bool {
    bytes[start..].starts_with(b"http://") || bytes[start..].starts_with(b"https://")
}

fn url_candidate_byte(byte: u8) -> bool {
    path_candidate_byte(byte)
        || matches!(
            byte,
            b'~' | b':' | b'%' | b'@' | b'?' | b'#' | b'=' | b'&' | b'+'
        )
}

fn unwrap_token(value: &str) -> &str {
    value.trim_matches(conventional_prose_delimiter)
}

fn conventional_prose_delimiter(character: char) -> bool {
    matches!(
        character,
        '`' | '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';'
    )
}

fn unsafe_path_candidate(candidate: &str) -> bool {
    candidate.starts_with('/')
        || has_drive_prefix(candidate)
        || candidate.split('/').any(|segment| segment == "..")
}

fn validate_http_url_at(bytes: &[u8], start: usize, operations: &mut usize) -> Result<usize, ()> {
    let authority_start = if bytes[start..].starts_with(b"https://") {
        start + b"https://".len()
    } else if bytes[start..].starts_with(b"http://") {
        start + b"http://".len()
    } else {
        return Err(());
    };
    let mut end = authority_start;
    while end < bytes.len() && url_candidate_byte(bytes[end]) {
        *operations = operations.saturating_add(1);
        end += 1;
    }
    let url = &bytes[authority_start..end];
    if url.iter().any(|byte| matches!(byte, b'@' | b'?' | b'#')) {
        return Err(());
    }
    let path_start = url.iter().position(|byte| *byte == b'/');
    let authority = &url[..path_start.unwrap_or(url.len())];
    if authority.is_empty()
        || authority
            .iter()
            .any(|byte| matches!(byte, b'@' | b'?' | b'#' | b'\\' | b'%'))
    {
        return Err(());
    }
    let colon_count = authority.iter().filter(|byte| **byte == b':').count();
    if colon_count > 1 {
        return Err(());
    }
    let (host, port) = authority
        .iter()
        .position(|byte| *byte == b':')
        .map_or((authority, None), |colon| {
            (&authority[..colon], Some(&authority[colon + 1..]))
        });
    if !valid_url_host(host)
        || port.is_some_and(|port| port.is_empty() || !port.iter().all(u8::is_ascii_digit))
    {
        return Err(());
    }

    if let Some(path_start) = path_start {
        validate_url_path(&url[path_start + 1..], operations)?;
    }
    Ok(end)
}

fn valid_url_host(host: &[u8]) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.first().is_some_and(u8::is_ascii_alphanumeric)
                && label.last().is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn validate_url_path(path: &[u8], operations: &mut usize) -> Result<(), ()> {
    let mut index = 0usize;
    let mut segment_len = 0usize;
    let mut segment_all_dots = true;
    while index <= path.len() {
        *operations = operations.saturating_add(1);
        if index == path.len() || path[index] == b'/' {
            if segment_all_dots && matches!(segment_len, 1 | 2) {
                return Err(());
            }
            segment_len = 0;
            segment_all_dots = true;
            index += 1;
            continue;
        }
        let decoded = if path[index] == b'%' {
            let high = *path.get(index + 1).ok_or(())?;
            let low = *path.get(index + 2).ok_or(())?;
            let decoded = decode_hex(high).and_then(|high| {
                decode_hex(low).map(|low| high.saturating_mul(16).saturating_add(low))
            });
            index += 3;
            decoded.ok_or(())?
        } else {
            let decoded = path[index];
            index += 1;
            decoded
        };
        if matches!(decoded, b'/' | b'\\') {
            return Err(());
        }
        segment_len = segment_len.saturating_add(1);
        segment_all_dots &= decoded == b'.';
    }
    Ok(())
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn credential_shaped(value: &str, safe_url_ranges: &[Range<usize>]) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("-----begin ")
        || (lower.contains("://") && lower.contains('@'))
        || CREDENTIAL_ASSIGNMENT.is_match(value)
        || AUTHORIZATION_VALUE.is_match(value)
        || KNOWN_CREDENTIAL_PREFIX.is_match(value)
    {
        return true;
    }
    let mut previous = None;
    let mut search_from = 0usize;
    let mut safe_url_index = 0usize;
    for raw in value.split_whitespace() {
        let raw_start = search_from
            + value[search_from..]
                .find(raw)
                .expect("split token remains inside source text");
        search_from = raw_start + raw.len();
        let token = unwrap_token(raw);
        let token_start = raw_start + raw.find(token).unwrap_or(0);
        if contextual_hash_assignment(token) {
            previous = Some(token);
            continue;
        }
        let rejected = TOKEN_CANDIDATE.find_iter(token).any(|candidate| {
            while safe_url_ranges
                .get(safe_url_index)
                .is_some_and(|range| range.end <= token_start + candidate.start())
            {
                safe_url_index += 1;
            }
            let inside_safe_url = safe_url_ranges.get(safe_url_index).is_some_and(|range| {
                range.start <= token_start + candidate.start()
                    && token_start + candidate.end() <= range.end
            });
            !inside_safe_url && high_entropy_standalone_token(token, candidate, previous)
        });
        if rejected {
            return true;
        }
        previous = Some(token);
    }
    false
}

pub(crate) fn contains_credential_material(value: &str) -> bool {
    let scan = scan_portable_text(value);
    credential_shaped(value, &scan.safe_url_ranges)
}

fn contextual_hash_assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(label, digest)| {
        let digest = unwrap_token(digest);
        contextual_hash_label(label)
            && !digest.is_empty()
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

fn high_entropy_standalone_token(
    container: &str,
    candidate: regex::Match<'_>,
    previous: Option<&str>,
) -> bool {
    let candidate_text = candidate.as_str();
    if (candidate_text
        .chars()
        .all(|character| character.is_ascii_hexdigit())
        && (contextual_hash(container, candidate.start())
            || previous.is_some_and(contextual_hash_label)))
        || benign_identifier(candidate_text)
        || benign_kebab_identifier(candidate_text)
        || portable_path_token(candidate_text)
    {
        return false;
    }
    let mut frequencies = [0usize; 128];
    for byte in candidate_text.bytes() {
        if byte.is_ascii() {
            frequencies[usize::from(byte)] += 1;
        }
    }
    let length = candidate_text.len() as f64;
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

fn contextual_hash(container: &str, candidate_start: usize) -> bool {
    let label = container[..candidate_start]
        .split_whitespace()
        .next_back()
        .map(|value| value.trim_matches(|character: char| !character.is_ascii_alphanumeric()))
        .unwrap_or("");
    contextual_hash_label(label)
}

fn contextual_hash_label(label: &str) -> bool {
    let label = label.trim_matches(|character: char| !character.is_ascii_alphanumeric());
    matches!(
        label.to_ascii_lowercase().as_str(),
        "commit" | "hash" | "sha" | "sha1" | "sha256" | "digest" | "fingerprint"
    )
}

fn benign_kebab_identifier(candidate: &str) -> bool {
    let segments = candidate.split('-').collect::<Vec<_>>();
    segments.len() >= 3
        && segments.iter().all(|segment| {
            segment.len() >= 2
                && segment
                    .chars()
                    .all(|character| character.is_ascii_lowercase())
        })
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
        && occurrence.map_or(true, |occurrence| {
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
struct PolicyUpdateCapability {
    requested_root: PathBuf,
    root: File,
    policy_dir: File,
    root_identity: unix_fs::Identity,
    directory_identity: unix_fs::Identity,
}

#[cfg(unix)]
fn open_update_capability(
    project_root: &Path,
    failure: WriteFailure,
) -> Result<PolicyUpdateCapability, CommandError> {
    let (root, policy_dir, created) = unix_fs::open_project_policy_dir(project_root, true)
        .map_err(|_| CommandError::policy_write_failed())?;
    if created {
        if failure == WriteFailure::AfterDirectoryCreateBeforeRootSync {
            return Err(CommandError::policy_write_failed());
        }
        root.sync_all()
            .map_err(|_| CommandError::policy_write_failed())?;
    }
    let root_identity =
        unix_fs::identity(&root).map_err(|_| CommandError::policy_write_failed())?;
    let directory_identity =
        unix_fs::identity(&policy_dir).map_err(|_| CommandError::policy_write_failed())?;
    let capability = PolicyUpdateCapability {
        requested_root: project_root.to_path_buf(),
        root,
        policy_dir,
        root_identity,
        directory_identity,
    };
    if !capability.requested_path_is_pinned() {
        return Err(CommandError::policy_write_failed());
    }
    Ok(capability)
}

#[cfg(unix)]
impl PolicyUpdateCapability {
    fn requested_path_is_pinned(&self) -> bool {
        unix_fs::path_has_identity(&self.requested_root, self.root_identity)
            && unix_fs::same_named_identity(&self.root, ".oxaudit", self.directory_identity)
    }
}

#[cfg(unix)]
fn load_policy_for_update(
    capability: &mut PolicyUpdateCapability,
    hook: &mut impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    if !capability.requested_path_is_pinned() {
        return Err(CommandError::policy_write_failed());
    }
    load_policy_from_unix_dir(&capability.policy_dir, hook)
}

#[cfg(unix)]
fn unix_named_snapshot(directory: &File, name: &str) -> Option<(unix_fs::Identity, Vec<u8>)> {
    let mut file = unix_fs::open_regular_at(directory, name, true).ok()?;
    let identity = unix_fs::identity(&file).ok()?;
    let bytes = unix_fs::read_bounded(&mut file, MAX_POLICY_BYTES).ok()?;
    if unix_fs::same_named_identity(directory, name, identity) {
        Some((identity, bytes))
    } else {
        None
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct UnixNamedState {
    identity: unix_fs::Identity,
    /// `None` deliberately represents a no-follow opaque object (for example,
    /// a symlink or FIFO). Such an object can be restored by atomic exchange,
    /// but is never opened or interpreted as policy bytes.
    bytes: Option<Vec<u8>>,
}

#[cfg(unix)]
fn unix_named_state(directory: &File, name: &str) -> std::io::Result<UnixNamedState> {
    let identity = unix_fs::named_identity(directory, name)?;
    match unix_fs::open_regular_at(directory, name, true) {
        Ok(mut file) => {
            let opened_identity = unix_fs::identity(&file)?;
            if opened_identity != identity
                || !unix_fs::same_named_identity(directory, name, identity)
            {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            let bytes = match unix_fs::read_bounded(&mut file, MAX_POLICY_BYTES) {
                Ok(bytes) => Some(bytes),
                Err(_) if unix_fs::same_named_identity(directory, name, identity) => None,
                Err(error) => return Err(error),
            };
            Ok(UnixNamedState { identity, bytes })
        }
        Err(_) if unix_fs::same_named_identity(directory, name, identity) => Ok(UnixNamedState {
            identity,
            bytes: None,
        }),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum UnixExchangeOutcome {
    Applied,
    Undone {
        authoritative_second: UnixNamedState,
    },
    Reconciled {
        authoritative_second: UnixNamedState,
    },
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnixUndoHookPoint {
    BeforeRecheck,
    AfterRecheck,
}

/// Exchanges two names and validates the state produced by the exchange. If
/// validation fails, it exchanges the names back only while both just-observed
/// states are still exact, then verifies the undo. This makes every reversal
/// use the same swap-then-validate transition instead of a check-then-swap gap.
#[cfg(unix)]
fn unix_exchange_or_undo(
    directory: &File,
    first: &str,
    second: &str,
    expected_first_after: &UnixNamedState,
    expected_second_after: &UnixNamedState,
    mut undo_hook: impl FnMut(UnixUndoHookPoint),
) -> std::io::Result<UnixExchangeOutcome> {
    unix_fs::exchange_at(directory, first, second)?;
    let observed_first = unix_named_state(directory, first)?;
    let observed_second = unix_named_state(directory, second)?;
    if &observed_first == expected_first_after && &observed_second == expected_second_after {
        return Ok(UnixExchangeOutcome::Applied);
    }

    undo_hook(UnixUndoHookPoint::BeforeRecheck);
    if unix_named_state(directory, first)? != observed_first
        || unix_named_state(directory, second)? != observed_second
    {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }
    undo_hook(UnixUndoHookPoint::AfterRecheck);
    unix_fs::exchange_at(directory, first, second)?;
    let after_undo_first = unix_named_state(directory, first)?;
    let after_undo_second = unix_named_state(directory, second)?;
    if after_undo_first == observed_second && after_undo_second == observed_first {
        directory.sync_all()?;
        return Ok(UnixExchangeOutcome::Undone {
            authoritative_second: after_undo_second,
        });
    }

    // A final-name edit in the recheck-to-exchange window moves to `first`.
    // Atomically compensate so that newest observed authoritative object is
    // placed back at `second`; preserve both names if either state moves again.
    if unix_named_state(directory, first)? != after_undo_first
        || unix_named_state(directory, second)? != after_undo_second
    {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }
    unix_fs::exchange_at(directory, first, second)?;
    let reconciled_first = unix_named_state(directory, first)?;
    let reconciled_second = unix_named_state(directory, second)?;
    if reconciled_first == after_undo_second && reconciled_second == after_undo_first {
        directory.sync_all()?;
        Ok(UnixExchangeOutcome::Reconciled {
            authoritative_second: reconciled_second,
        })
    } else {
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    }
}

/// Restores an initially absent target by atomically retiring the published
/// name to a unique quarantine. Only an exact candidate is deleted. Anything
/// else is moved back no-clobber; if a newer target appeared, both are kept.
#[cfg(unix)]
fn unix_restore_absence(
    directory: &File,
    candidate_identity: unix_fs::Identity,
    candidate_bytes: &[u8],
) -> std::io::Result<bool> {
    let quarantine = format!(".policy.json.{}.rollback-absent", Uuid::new_v4());
    unix_fs::rename_noreplace_at(directory, "policy.json", &quarantine)?;
    let moved = unix_named_state(directory, &quarantine)?;
    let candidate = UnixNamedState {
        identity: candidate_identity,
        bytes: Some(candidate_bytes.to_vec()),
    };
    if moved == candidate && unix_named_state(directory, &quarantine)? == candidate {
        unix_fs::unlink_at(directory, &quarantine)?;
        directory.sync_all()?;
        return Ok(true);
    }

    if unix_named_state(directory, &quarantine)? != moved {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }
    unix_fs::rename_noreplace_at(directory, &quarantine, "policy.json")?;
    if unix_named_state(directory, "policy.json")? != moved {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }
    directory.sync_all()?;
    Ok(false)
}

#[cfg(unix)]
fn unix_named_bytes_equal(
    directory: &File,
    name: &str,
    identity: unix_fs::Identity,
    expected: &[u8],
) -> bool {
    unix_named_snapshot(directory, name)
        .is_some_and(|(actual_identity, bytes)| actual_identity == identity && bytes == expected)
}

#[cfg(unix)]
fn unix_named_valid_candidate(
    directory: &File,
    name: &str,
    identity: unix_fs::Identity,
    expected: &[u8],
) -> bool {
    let Some((actual_identity, bytes)) = unix_named_snapshot(directory, name) else {
        return false;
    };
    actual_identity == identity
        && bytes == expected
        && parse_and_validate(&bytes, ValidationMode::Load).is_ok()
}

#[cfg(unix)]
fn unix_terminal_for_authoritative(
    directory: &File,
    authoritative: &UnixNamedState,
    candidate: &UnixNamedState,
) -> PolicyWriteTerminal {
    if directory.sync_all().is_err() {
        return PolicyWriteTerminal::Indeterminate;
    }
    let Ok(final_state) = unix_named_state(directory, "policy.json") else {
        return PolicyWriteTerminal::Indeterminate;
    };
    if &final_state != authoritative {
        return PolicyWriteTerminal::Indeterminate;
    }
    if &final_state == candidate
        && final_state
            .bytes
            .as_deref()
            .is_some_and(|bytes| parse_and_validate(bytes, ValidationMode::Load).is_ok())
    {
        PolicyWriteTerminal::CandidateDurablyCommitted
    } else {
        PolicyWriteTerminal::PriorOrNewerAuthoritative
    }
}

#[cfg(unix)]
fn unix_finish_rollback(
    directory: &File,
    temp_name: &str,
    recovery: &mut unix_fs::OwnedName<'_>,
    candidate: &UnixNamedState,
    requested_authoritative: &UnixNamedState,
    outcome: std::io::Result<UnixExchangeOutcome>,
) -> PolicyWriteTerminal {
    match outcome {
        Ok(UnixExchangeOutcome::Applied) => {
            let terminal =
                unix_terminal_for_authoritative(directory, requested_authoritative, candidate);
            recovery.disarm();
            let mut candidate_cleanup =
                unix_fs::OwnedName::new(directory, temp_name.to_owned(), candidate.identity);
            if terminal != PolicyWriteTerminal::Indeterminate
                && candidate.bytes.as_deref().is_some_and(|bytes| {
                    unix_named_bytes_equal(directory, temp_name, candidate.identity, bytes)
                })
            {
                let _ = candidate_cleanup.remove();
            } else {
                candidate_cleanup.disarm();
            }
            terminal
        }
        Ok(UnixExchangeOutcome::Undone {
            authoritative_second,
        })
        | Ok(UnixExchangeOutcome::Reconciled {
            authoritative_second,
        }) => {
            recovery.disarm();
            unix_terminal_for_authoritative(directory, &authoritative_second, candidate)
        }
        Err(_) => {
            recovery.disarm();
            PolicyWriteTerminal::Indeterminate
        }
    }
}

#[cfg(unix)]
fn atomic_write_policy(
    capability: &mut PolicyUpdateCapability,
    bytes: &[u8],
    expected_bytes: Option<&[u8]>,
    failure: WriteFailure,
    hook: &mut impl FnMut(IoStage),
) -> Result<PolicyWriteTerminal, CommandError> {
    hook(IoStage::BeforeTempCreate);
    if !capability.requested_path_is_pinned() {
        return Err(CommandError::policy_write_failed());
    }

    let temp_name = format!(".policy.json.{}.tmp", Uuid::new_v4());
    let mut temp = unix_fs::create_new_at(&capability.policy_dir, &temp_name)
        .map_err(|_| CommandError::policy_write_failed())?;
    let temp_identity =
        unix_fs::identity(&temp).map_err(|_| CommandError::policy_write_failed())?;
    let mut temp_cleanup =
        unix_fs::OwnedName::new(&capability.policy_dir, temp_name.clone(), temp_identity);
    temp.write_all(bytes)
        .and_then(|_| temp.flush())
        .and_then(|_| temp.sync_all())
        .map_err(|_| CommandError::policy_write_failed())?;
    hook(IoStage::AfterTempSync);
    if failure == WriteFailure::AfterTempSync {
        return Err(CommandError::policy_write_failed());
    }
    if !capability.requested_path_is_pinned()
        || !unix_fs::same_named_identity(&capability.policy_dir, &temp_name, temp_identity)
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
    if !capability.requested_path_is_pinned() {
        return Err(CommandError::policy_write_failed());
    }
    let current = match unix_fs::open_regular_at(&capability.policy_dir, "policy.json", true) {
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
    hook(IoStage::AfterPolicyPreflight);
    if !capability.requested_path_is_pinned()
        || !unix_fs::same_named_identity(&capability.policy_dir, &temp_name, temp_identity)
    {
        return Err(CommandError::policy_write_failed());
    }

    let candidate_state = UnixNamedState {
        identity: temp_identity,
        bytes: Some(bytes.to_vec()),
    };

    let Some(expected) = expected_bytes else {
        unix_fs::link_at(&capability.policy_dir, &temp_name, "policy.json")
            .map_err(|_| CommandError::policy_write_failed())?;
        hook(IoStage::AfterReplace);

        let candidate_is_untouched =
            unix_named_bytes_equal(&capability.policy_dir, "policy.json", temp_identity, bytes)
                && unix_named_bytes_equal(&capability.policy_dir, &temp_name, temp_identity, bytes);
        if failure == WriteFailure::AfterReplaceBeforeDirectorySync || !candidate_is_untouched {
            let terminal = if candidate_is_untouched {
                hook(IoStage::BeforeRollbackExchange);
                match unix_restore_absence(&capability.policy_dir, temp_identity, bytes) {
                    Ok(_) => PolicyWriteTerminal::PriorOrNewerAuthoritative,
                    Err(_) => unix_named_state(&capability.policy_dir, "policy.json").map_or(
                        PolicyWriteTerminal::Indeterminate,
                        |state| {
                            unix_terminal_for_authoritative(
                                &capability.policy_dir,
                                &state,
                                &candidate_state,
                            )
                        },
                    ),
                }
            } else {
                temp_cleanup.disarm();
                unix_named_state(&capability.policy_dir, "policy.json").map_or(
                    PolicyWriteTerminal::Indeterminate,
                    |state| {
                        unix_terminal_for_authoritative(
                            &capability.policy_dir,
                            &state,
                            &candidate_state,
                        )
                    },
                )
            };
            return Ok(terminal);
        }
        if capability.policy_dir.sync_all().is_err() {
            hook(IoStage::BeforeRollbackExchange);
            let terminal = if unix_named_bytes_equal(
                &capability.policy_dir,
                "policy.json",
                temp_identity,
                bytes,
            ) && unix_named_bytes_equal(
                &capability.policy_dir,
                &temp_name,
                temp_identity,
                bytes,
            ) {
                match unix_restore_absence(&capability.policy_dir, temp_identity, bytes) {
                    Ok(_) => PolicyWriteTerminal::PriorOrNewerAuthoritative,
                    Err(_) => unix_named_state(&capability.policy_dir, "policy.json").map_or(
                        PolicyWriteTerminal::Indeterminate,
                        |state| {
                            unix_terminal_for_authoritative(
                                &capability.policy_dir,
                                &state,
                                &candidate_state,
                            )
                        },
                    ),
                }
            } else {
                unix_named_state(&capability.policy_dir, "policy.json").map_or(
                    PolicyWriteTerminal::Indeterminate,
                    |state| {
                        unix_terminal_for_authoritative(
                            &capability.policy_dir,
                            &state,
                            &candidate_state,
                        )
                    },
                )
            };
            return Ok(terminal);
        }
        if !unix_named_valid_candidate(&capability.policy_dir, "policy.json", temp_identity, bytes)
        {
            temp_cleanup.disarm();
            return Ok(
                unix_named_state(&capability.policy_dir, "policy.json").map_or(
                    PolicyWriteTerminal::Indeterminate,
                    |state| {
                        unix_terminal_for_authoritative(
                            &capability.policy_dir,
                            &state,
                            &candidate_state,
                        )
                    },
                ),
            );
        }
        let _ = temp_cleanup
            .remove()
            .and_then(|_| capability.policy_dir.sync_all());
        return Ok(PolicyWriteTerminal::CandidateDurablyCommitted);
    };

    let Some((_, current_identity)) = current else {
        return Err(CommandError::policy_write_failed());
    };
    let old_state = UnixNamedState {
        identity: current_identity,
        bytes: Some(expected.to_vec()),
    };
    let publication = unix_exchange_or_undo(
        &capability.policy_dir,
        &temp_name,
        "policy.json",
        &old_state,
        &candidate_state,
        |point| match point {
            UnixUndoHookPoint::BeforeRecheck => hook(IoStage::BeforeRollbackExchange),
            UnixUndoHookPoint::AfterRecheck => hook(IoStage::AfterRollbackRecheckBeforeUndo),
        },
    );
    match publication {
        Ok(UnixExchangeOutcome::Applied) => {}
        Ok(UnixExchangeOutcome::Undone {
            authoritative_second,
        }) => {
            return Ok(unix_terminal_for_authoritative(
                &capability.policy_dir,
                &authoritative_second,
                &candidate_state,
            ));
        }
        Ok(UnixExchangeOutcome::Reconciled {
            authoritative_second,
        }) => {
            temp_cleanup.disarm();
            return Ok(unix_terminal_for_authoritative(
                &capability.policy_dir,
                &authoritative_second,
                &candidate_state,
            ));
        }
        Err(_) => {
            // The exchange state is indeterminate. Cleanup must not remove a
            // name that may now contain externally supplied bytes.
            temp_cleanup.disarm();
            return Ok(PolicyWriteTerminal::Indeterminate);
        }
    }
    temp_cleanup.disarm();
    let mut recovery =
        unix_fs::OwnedName::new(&capability.policy_dir, temp_name.clone(), current_identity);

    hook(IoStage::AfterReplace);

    let must_rollback = failure == WriteFailure::AfterReplaceBeforeDirectorySync
        || !unix_named_bytes_equal(&capability.policy_dir, "policy.json", temp_identity, bytes)
        || !unix_named_bytes_equal(
            &capability.policy_dir,
            &temp_name,
            current_identity,
            expected,
        );
    if must_rollback {
        hook(IoStage::BeforeRollbackExchange);
        let rollback = unix_exchange_or_undo(
            &capability.policy_dir,
            &temp_name,
            "policy.json",
            &candidate_state,
            &old_state,
            |point| {
                if point == UnixUndoHookPoint::AfterRecheck {
                    hook(IoStage::AfterRollbackRecheckBeforeUndo);
                }
            },
        );
        return Ok(unix_finish_rollback(
            &capability.policy_dir,
            &temp_name,
            &mut recovery,
            &candidate_state,
            &old_state,
            rollback,
        ));
    }

    if capability.policy_dir.sync_all().is_err() {
        hook(IoStage::BeforeRollbackExchange);
        let rollback = unix_exchange_or_undo(
            &capability.policy_dir,
            &temp_name,
            "policy.json",
            &candidate_state,
            &old_state,
            |point| {
                if point == UnixUndoHookPoint::AfterRecheck {
                    hook(IoStage::AfterRollbackRecheckBeforeUndo);
                }
            },
        );
        return Ok(unix_finish_rollback(
            &capability.policy_dir,
            &temp_name,
            &mut recovery,
            &candidate_state,
            &old_state,
            rollback,
        ));
    }
    if !unix_named_valid_candidate(&capability.policy_dir, "policy.json", temp_identity, bytes) {
        recovery.disarm();
        return Ok(
            unix_named_state(&capability.policy_dir, "policy.json").map_or(
                PolicyWriteTerminal::Indeterminate,
                |state| {
                    unix_terminal_for_authoritative(
                        &capability.policy_dir,
                        &state,
                        &candidate_state,
                    )
                },
            ),
        );
    }
    let terminal =
        unix_terminal_for_authoritative(&capability.policy_dir, &candidate_state, &candidate_state);
    if terminal == PolicyWriteTerminal::CandidateDurablyCommitted {
        let _ = recovery
            .remove()
            .and_then(|_| capability.policy_dir.sync_all());
    } else {
        recovery.disarm();
    }
    Ok(terminal)
}

#[cfg(windows)]
struct PolicyUpdateCapability {
    requested_root: PathBuf,
    root: std::fs::File,
    policy_dir_path: PathBuf,
    policy_dir: std::fs::File,
    root_identity: windows_fs::Identity,
    directory_identity: windows_fs::Identity,
}

#[cfg(windows)]
fn open_update_capability(
    project_root: &Path,
    _failure: WriteFailure,
) -> Result<PolicyUpdateCapability, CommandError> {
    let root = windows_fs::open_pinned_directory(project_root)
        .map_err(|_| CommandError::policy_write_failed())?;
    let root_identity =
        windows_fs::identity(&root).map_err(|_| CommandError::policy_write_failed())?;
    let policy_dir_path = project_root.join(".oxaudit");
    match windows_fs::open_directory(&policy_dir_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&policy_dir_path).map_err(|_| CommandError::policy_write_failed())?;
        }
        Err(_) => return Err(CommandError::policy_write_failed()),
    }
    let policy_dir = windows_fs::open_pinned_directory(&policy_dir_path)
        .map_err(|_| CommandError::policy_write_failed())?;
    let directory_identity =
        windows_fs::identity(&policy_dir).map_err(|_| CommandError::policy_write_failed())?;
    let capability = PolicyUpdateCapability {
        requested_root: project_root.to_path_buf(),
        root,
        policy_dir_path,
        policy_dir,
        root_identity,
        directory_identity,
    };
    if !capability.requested_path_is_pinned() {
        return Err(CommandError::policy_write_failed());
    }
    Ok(capability)
}

#[cfg(windows)]
impl PolicyUpdateCapability {
    fn requested_path_is_pinned(&self) -> bool {
        windows_fs::path_has_identity(&self.requested_root, self.root_identity, true)
            && windows_fs::path_has_identity(&self.policy_dir_path, self.directory_identity, true)
            && windows_fs::identity(&self.root).is_ok_and(|value| value == self.root_identity)
            && windows_fs::identity(&self.policy_dir)
                .is_ok_and(|value| value == self.directory_identity)
    }
}

#[cfg(windows)]
fn load_policy_for_update(
    capability: &mut PolicyUpdateCapability,
    hook: &mut impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    if !capability.requested_path_is_pinned() {
        return Err(CommandError::policy_write_failed());
    }
    hook(IoStage::BeforePolicyOpen);
    let mut policy = match windows_fs::open_regular(&capability.policy_dir_path.join("policy.json"))
    {
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

#[cfg(windows)]
fn windows_named_snapshot(path: &Path) -> Option<(windows_fs::Identity, Vec<u8>)> {
    let mut file = windows_fs::open_regular(path).ok()?;
    let identity = windows_fs::identity(&file).ok()?;
    let bytes = windows_fs::read_bounded(&mut file, MAX_POLICY_BYTES).ok()?;
    if windows_fs::path_has_identity(path, identity, false) {
        Some((identity, bytes))
    } else {
        None
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsNamedState {
    identity: windows_fs::Identity,
    bytes: Option<Vec<u8>>,
}

#[cfg(windows)]
fn windows_named_state(path: &Path) -> std::io::Result<WindowsNamedState> {
    let mut file = windows_fs::open_path_object(path)?;
    let identity = windows_fs::identity(&file)?;
    if !windows_fs::path_has_object_identity(path, identity) {
        return Err(std::io::Error::from_raw_os_error(5));
    }
    let metadata = file.metadata()?;
    let is_plain_file = metadata.is_file() && !windows_fs::is_reparse(&metadata);
    let bytes = match is_plain_file {
        true => match windows_fs::read_bounded(&mut file, MAX_POLICY_BYTES) {
            Ok(bytes) => Some(bytes),
            Err(_) if windows_fs::path_has_object_identity(path, identity) => None,
            Err(error) => return Err(error),
        },
        false => None,
    };
    Ok(WindowsNamedState { identity, bytes })
}

#[cfg(windows)]
enum WindowsRestoreOutcome {
    Applied(WindowsOwnedPath),
    Undone {
        authoritative_target: WindowsNamedState,
        preserved_recovery: WindowsOwnedPath,
    },
    Reconciled {
        authoritative_target: WindowsNamedState,
    },
}

/// Atomically installs `recovery` while capturing the displaced target. The
/// displaced file is the compare-and-swap witness. A mismatch is itself undone
/// with ReplaceFileW so a late external target is restored atomically.
#[cfg(windows)]
fn windows_restore_or_undo(
    target: &Path,
    recovery: &mut WindowsOwnedPath,
    expected_recovery: &WindowsNamedState,
    expected_target: &WindowsNamedState,
    hook: &mut impl FnMut(IoStage),
) -> std::io::Result<WindowsRestoreOutcome> {
    if !recovery.armed || !windows_fs::path_has_object_identity(&recovery.path, recovery.identity) {
        return Err(std::io::Error::from_raw_os_error(5));
    }
    let directory = target
        .parent()
        .ok_or_else(|| std::io::Error::from_raw_os_error(5))?;
    let displaced_path = directory.join(format!(
        ".policy.json.{}.rollback-displaced",
        Uuid::new_v4()
    ));
    windows_fs::durable_replace(target, &recovery.path, true, Some(&displaced_path))?;
    recovery.disarm();

    let observed_target = windows_named_state(target)?;
    let observed_displaced = windows_named_state(&displaced_path)?;
    if &observed_target == expected_recovery && &observed_displaced == expected_target {
        let target_file = windows_fs::open_regular_read_write(target)?;
        target_file.sync_all()?;
        if windows_named_state(target)? != observed_target
            || windows_named_state(&displaced_path)? != observed_displaced
        {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        return Ok(WindowsRestoreOutcome::Applied(WindowsOwnedPath::new(
            displaced_path,
            observed_displaced.identity,
        )));
    }

    if windows_named_state(target)? != observed_target
        || windows_named_state(&displaced_path)? != observed_displaced
    {
        return Err(std::io::Error::from_raw_os_error(5));
    }
    hook(IoStage::AfterRollbackRecheckBeforeUndo);
    let undo_backup = directory.join(format!(".policy.json.{}.rollback-old", Uuid::new_v4()));
    windows_fs::durable_replace(target, &displaced_path, true, Some(&undo_backup))?;
    let restored_target = windows_named_state(target)?;
    let preserved_old = windows_named_state(&undo_backup)?;
    if restored_target == observed_displaced && preserved_old == observed_target {
        windows_fs::open_regular_read_write(target)?.sync_all()?;
        return Ok(WindowsRestoreOutcome::Undone {
            authoritative_target: restored_target,
            preserved_recovery: WindowsOwnedPath::new(undo_backup, preserved_old.identity),
        });
    }

    if windows_named_state(target)? != restored_target
        || windows_named_state(&undo_backup)? != preserved_old
    {
        return Err(std::io::Error::from_raw_os_error(5));
    }
    let compensation = directory.join(format!(
        ".policy.json.{}.rollback-compensation",
        Uuid::new_v4()
    ));
    windows_fs::durable_replace(target, &undo_backup, true, Some(&compensation))?;
    let reconciled_target = windows_named_state(target)?;
    let preserved_displaced = windows_named_state(&compensation)?;
    if reconciled_target == preserved_old && preserved_displaced == restored_target {
        windows_fs::open_regular_read_write(target)?.sync_all()?;
        Ok(WindowsRestoreOutcome::Reconciled {
            authoritative_target: reconciled_target,
        })
    } else {
        Err(std::io::Error::from_raw_os_error(5))
    }
}

#[cfg(windows)]
fn windows_restore_absence(
    target: &Path,
    candidate_identity: windows_fs::Identity,
    candidate_bytes: &[u8],
) -> std::io::Result<bool> {
    let directory = target
        .parent()
        .ok_or_else(|| std::io::Error::from_raw_os_error(5))?;
    let quarantine = directory.join(format!(".policy.json.{}.rollback-absent", Uuid::new_v4()));
    windows_fs::move_noreplace(target, &quarantine)?;
    let moved = windows_named_state(&quarantine)?;
    let candidate = WindowsNamedState {
        identity: candidate_identity,
        bytes: Some(candidate_bytes.to_vec()),
    };
    if moved == candidate && windows_named_state(&quarantine)? == candidate {
        fs::remove_file(&quarantine)?;
        return Ok(true);
    }

    if windows_named_state(&quarantine)? != moved {
        return Err(std::io::Error::from_raw_os_error(5));
    }
    windows_fs::move_noreplace(&quarantine, target)?;
    if windows_named_state(target)? == moved {
        windows_fs::open_regular_read_write(target)?.sync_all()?;
        Ok(false)
    } else {
        Err(std::io::Error::from_raw_os_error(5))
    }
}

#[cfg(windows)]
fn windows_named_bytes_equal(path: &Path, identity: windows_fs::Identity, expected: &[u8]) -> bool {
    windows_named_snapshot(path)
        .is_some_and(|(actual_identity, bytes)| actual_identity == identity && bytes == expected)
}

#[cfg(windows)]
fn windows_terminal_for_authoritative(
    policy_path: &Path,
    authoritative: &WindowsNamedState,
    candidate: &WindowsNamedState,
) -> PolicyWriteTerminal {
    let Ok(current) = windows_named_state(policy_path) else {
        return PolicyWriteTerminal::Indeterminate;
    };
    if &current != authoritative {
        return PolicyWriteTerminal::Indeterminate;
    }
    if &current == candidate {
        if windows_fs::open_regular_read_write(policy_path)
            .and_then(|file| file.sync_all())
            .is_err()
            || !windows_named_state(policy_path).is_ok_and(|state| state == current)
        {
            PolicyWriteTerminal::Indeterminate
        } else {
            PolicyWriteTerminal::CandidateDurablyCommitted
        }
    } else {
        PolicyWriteTerminal::PriorOrNewerAuthoritative
    }
}

#[cfg(windows)]
fn windows_terminal_for_missing_or_current(
    policy_path: &Path,
    candidate: &WindowsNamedState,
) -> PolicyWriteTerminal {
    match windows_named_state(policy_path) {
        Ok(state) => windows_terminal_for_authoritative(policy_path, &state, candidate),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PolicyWriteTerminal::PriorOrNewerAuthoritative
        }
        Err(_) => PolicyWriteTerminal::Indeterminate,
    }
}

#[cfg(windows)]
fn windows_finish_restore(
    policy_path: &Path,
    backup: &mut WindowsOwnedPath,
    candidate: &WindowsNamedState,
    requested_authoritative: &WindowsNamedState,
    outcome: std::io::Result<WindowsRestoreOutcome>,
) -> PolicyWriteTerminal {
    match outcome {
        Ok(WindowsRestoreOutcome::Applied(mut displaced)) => {
            backup.disarm();
            let terminal =
                windows_terminal_for_authoritative(policy_path, requested_authoritative, candidate);
            if terminal != PolicyWriteTerminal::Indeterminate {
                if let Some(bytes) = candidate.bytes.as_deref() {
                    let _ = displaced.remove_if_exact(bytes);
                } else {
                    displaced.disarm();
                }
            } else {
                displaced.disarm();
            }
            terminal
        }
        Ok(WindowsRestoreOutcome::Undone {
            authoritative_target,
            mut preserved_recovery,
        }) => {
            backup.disarm();
            let terminal =
                windows_terminal_for_authoritative(policy_path, &authoritative_target, candidate);
            if terminal == PolicyWriteTerminal::PriorOrNewerAuthoritative {
                if let Some(bytes) = windows_named_state(&preserved_recovery.path)
                    .ok()
                    .and_then(|state| state.bytes)
                {
                    let _ = preserved_recovery.remove_if_exact(&bytes);
                } else {
                    preserved_recovery.disarm();
                }
            } else {
                // A rollback that was undone to the exact candidate is a
                // committed success; retain the changed recovery witness.
                preserved_recovery.disarm();
            }
            terminal
        }
        Ok(WindowsRestoreOutcome::Reconciled {
            authoritative_target,
        }) => {
            backup.disarm();
            windows_terminal_for_authoritative(policy_path, &authoritative_target, candidate)
        }
        Err(_) => {
            backup.disarm();
            PolicyWriteTerminal::Indeterminate
        }
    }
}

#[cfg(windows)]
fn atomic_write_policy(
    capability: &mut PolicyUpdateCapability,
    bytes: &[u8],
    expected_bytes: Option<&[u8]>,
    failure: WriteFailure,
    hook: &mut impl FnMut(IoStage),
) -> Result<PolicyWriteTerminal, CommandError> {
    hook(IoStage::BeforeTempCreate);
    if !capability.requested_path_is_pinned() {
        return Err(CommandError::policy_write_failed());
    }

    let temp_path = capability
        .policy_dir_path
        .join(format!(".policy.json.{}.tmp", Uuid::new_v4()));
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
        || !capability.requested_path_is_pinned()
    {
        return Err(CommandError::policy_write_failed());
    }
    let persisted = windows_fs::read_bounded(&mut temp, MAX_POLICY_BYTES)
        .map_err(|_| CommandError::policy_write_failed())?;
    if persisted != bytes || parse_and_validate(&persisted, ValidationMode::Load).is_err() {
        return Err(CommandError::policy_write_failed());
    }
    // ReplaceFileW and MoveFileExW operate on the temp pathname. Keep this
    // close explicit: Rust's lexical scope is not the Win32 sharing contract.
    drop(temp);

    hook(IoStage::BeforeReplace);
    let policy_path = capability.policy_dir_path.join("policy.json");
    let current = match windows_named_state(&policy_path) {
        Ok(state) => Some(state),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(CommandError::policy_write_failed()),
    };
    if current.as_ref().and_then(|state| state.bytes.as_deref()) != expected_bytes
        || !capability.requested_path_is_pinned()
        || !windows_fs::path_has_identity(&temp_path, temp_identity, false)
    {
        return Err(CommandError::policy_write_failed());
    }
    hook(IoStage::AfterPolicyPreflight);
    if !capability.requested_path_is_pinned()
        || !windows_fs::path_has_identity(&temp_path, temp_identity, false)
    {
        return Err(CommandError::policy_write_failed());
    }

    let backup_path = capability
        .policy_dir_path
        .join(format!(".policy.json.{}.recovery", Uuid::new_v4()));
    let had_policy = current.is_some();
    let candidate_state = WindowsNamedState {
        identity: temp_identity,
        bytes: Some(bytes.to_vec()),
    };
    if windows_fs::durable_replace(
        &policy_path,
        &temp_path,
        had_policy,
        had_policy.then_some(backup_path.as_path()),
    )
    .is_err()
    {
        // A failed Win32 namespace operation is treated conservatively: do
        // not clean either pathname until the named terminal state is known.
        cleanup.disarm();
        return Ok(windows_terminal_for_missing_or_current(
            &policy_path,
            &candidate_state,
        ));
    }
    cleanup.disarm();
    if !had_policy {
        let installed = windows_fs::open_regular_read_write(&policy_path)
            .and_then(|file| file.sync_all())
            .is_ok()
            && windows_named_bytes_equal(&policy_path, temp_identity, bytes);
        hook(IoStage::AfterReplace);
        let still_installed = windows_named_bytes_equal(&policy_path, temp_identity, bytes);
        if failure == WriteFailure::AfterReplaceBeforeDirectorySync
            || !installed
            || !still_installed
        {
            let terminal = if windows_named_bytes_equal(&policy_path, temp_identity, bytes) {
                hook(IoStage::BeforeRollbackExchange);
                if windows_named_bytes_equal(&policy_path, temp_identity, bytes) {
                    match windows_restore_absence(&policy_path, temp_identity, bytes) {
                        Ok(_) => PolicyWriteTerminal::PriorOrNewerAuthoritative,
                        Err(_) => {
                            windows_terminal_for_missing_or_current(&policy_path, &candidate_state)
                        }
                    }
                } else {
                    windows_terminal_for_missing_or_current(&policy_path, &candidate_state)
                }
            } else {
                windows_terminal_for_missing_or_current(&policy_path, &candidate_state)
            };
            return Ok(terminal);
        }
        return Ok(windows_terminal_for_authoritative(
            &policy_path,
            &candidate_state,
            &candidate_state,
        ));
    }

    let backup_state = match windows_named_state(&backup_path) {
        Ok(state) => state,
        Err(_) => return Ok(PolicyWriteTerminal::Indeterminate),
    };
    let mut backup = WindowsOwnedPath::new(backup_path.clone(), backup_state.identity);
    let Some(expected_old) = current.as_ref() else {
        backup.disarm();
        return Ok(PolicyWriteTerminal::Indeterminate);
    };
    if backup_state != *expected_old {
        hook(IoStage::BeforeRollbackExchange);
        let restored = windows_restore_or_undo(
            &policy_path,
            &mut backup,
            &backup_state,
            &candidate_state,
            hook,
        );
        return Ok(windows_finish_restore(
            &policy_path,
            &mut backup,
            &candidate_state,
            &backup_state,
            restored,
        ));
    }
    let installed = windows_fs::open_regular_read_write(&policy_path)
        .and_then(|file| file.sync_all())
        .is_ok()
        && windows_named_bytes_equal(&policy_path, temp_identity, bytes);
    hook(IoStage::AfterReplace);
    if failure == WriteFailure::AfterReplaceBeforeDirectorySync
        || !installed
        || !windows_named_bytes_equal(&policy_path, temp_identity, bytes)
        || !windows_named_bytes_equal(
            &backup_path,
            backup_state.identity,
            expected_bytes.unwrap_or_default(),
        )
    {
        hook(IoStage::BeforeRollbackExchange);
        let restored = windows_restore_or_undo(
            &policy_path,
            &mut backup,
            expected_old,
            &candidate_state,
            hook,
        );
        return Ok(windows_finish_restore(
            &policy_path,
            &mut backup,
            &candidate_state,
            expected_old,
            restored,
        ));
    }
    if parse_and_validate(bytes, ValidationMode::Load).is_err() {
        hook(IoStage::BeforeRollbackExchange);
        let restored = windows_restore_or_undo(
            &policy_path,
            &mut backup,
            expected_old,
            &candidate_state,
            hook,
        );
        return Ok(windows_finish_restore(
            &policy_path,
            &mut backup,
            &candidate_state,
            expected_old,
            restored,
        ));
    }
    let terminal =
        windows_terminal_for_authoritative(&policy_path, &candidate_state, &candidate_state);
    if terminal == PolicyWriteTerminal::CandidateDurablyCommitted {
        let _ = backup.remove_if_exact(expected_bytes.unwrap_or_default());
    } else {
        backup.disarm();
    }
    Ok(terminal)
}

#[cfg(not(any(unix, windows)))]
struct PolicyUpdateCapability {
    project_root: PathBuf,
}

#[cfg(not(any(unix, windows)))]
fn open_update_capability(
    project_root: &Path,
    _failure: WriteFailure,
) -> Result<PolicyUpdateCapability, CommandError> {
    Ok(PolicyUpdateCapability {
        project_root: project_root.to_path_buf(),
    })
}

#[cfg(not(any(unix, windows)))]
fn load_policy_for_update(
    capability: &mut PolicyUpdateCapability,
    hook: &mut impl FnMut(IoStage),
) -> Result<LoadedPolicy, CommandError> {
    load_policy_with_hook(&capability.project_root, hook)
}

#[cfg(not(any(unix, windows)))]
fn atomic_write_policy(
    capability: &mut PolicyUpdateCapability,
    bytes: &[u8],
    expected_bytes: Option<&[u8]>,
    failure: WriteFailure,
    hook: &mut impl FnMut(IoStage),
) -> Result<PolicyWriteTerminal, CommandError> {
    let project_root = &capability.project_root;
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
        return Ok(PolicyWriteTerminal::Indeterminate);
    }
    Ok(PolicyWriteTerminal::CandidateDurablyCommitted)
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

    fn pinned_options() -> OpenOptions {
        let mut options = OpenOptions::new();
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
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

    pub(super) fn open_pinned_directory(path: &Path) -> io::Result<File> {
        let mut options = pinned_options();
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

    pub(super) fn open_path_object(path: &Path) -> io::Result<File> {
        let mut options = shared_options();
        options
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path)
    }

    pub(super) fn is_reparse(metadata: &std::fs::Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    pub(super) fn open_regular_read_write(path: &Path) -> io::Result<File> {
        let mut options = shared_options();
        options
            .read(true)
            .write(true)
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

    pub(super) fn path_has_object_identity(path: &Path, expected: Identity) -> bool {
        open_path_object(path)
            .and_then(|file| identity(&file))
            .is_ok_and(|actual| actual == expected)
    }

    /// Existing targets use ReplaceFileW with its supported zero flags and an
    /// optional attempt-owned backup; the caller flushes the installed file.
    /// Initially missing targets use MoveFileExW with write-through.
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
                    0,
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

    pub(super) fn move_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        durable_replace(to, from, false, None)
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
        if self.armed && windows_fs::path_has_object_identity(&self.path, self.identity) {
            fs::remove_file(&self.path)?;
        }
        self.armed = false;
        Ok(())
    }

    fn remove_if_exact(&mut self, expected: &[u8]) -> std::io::Result<()> {
        if !self.armed || !windows_named_bytes_equal(&self.path, self.identity, expected) {
            self.disarm();
            return Err(std::io::Error::from_raw_os_error(5));
        }
        fs::remove_file(&self.path)?;
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

    pub(super) fn path_has_identity(path: &Path, expected: Identity) -> bool {
        path.canonicalize()
            .and_then(|canonical| open_directory(&canonical))
            .and_then(|directory| identity(&directory))
            .is_ok_and(|actual| actual == expected)
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

    pub(super) fn exchange_at(directory: &File, first: &str, second: &str) -> io::Result<()> {
        let first = c_name(first)?;
        let second = c_name(second)?;
        #[cfg(target_vendor = "apple")]
        let result = unsafe {
            libc::renameatx_np(
                directory.as_raw_fd(),
                first.as_ptr(),
                directory.as_raw_fd(),
                second.as_ptr(),
                libc::RENAME_SWAP,
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                directory.as_raw_fd(),
                first.as_ptr(),
                directory.as_raw_fd(),
                second.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
        let result = {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "atomic exchange is unavailable",
            ));
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn rename_noreplace_at(directory: &File, from: &str, to: &str) -> io::Result<()> {
        let from = c_name(from)?;
        let to = c_name(to)?;
        #[cfg(target_vendor = "apple")]
        let result = unsafe {
            libc::renameatx_np(
                directory.as_raw_fd(),
                from.as_ptr(),
                directory.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                directory.as_raw_fd(),
                from.as_ptr(),
                directory.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
        let result = {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "atomic no-clobber rename is unavailable",
            ));
        };
        if result == 0 {
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
    fn short_credentials_and_auth_schemes_are_rejected() {
        for value in [
            "pwd=x",
            "password = x",
            "api key: z",
            "Bearer abc",
            "Basic abc",
            "sk-live",
            "ghp_x",
        ] {
            assert!(!safe_required_text(value), "accepted fixture {value:?}");
        }
    }

    #[test]
    fn standalone_high_entropy_hex_is_rejected_but_contextual_hashes_are_allowed() {
        assert!(!safe_required_text(
            "a9f73c6d14e82b05f7c9134da6e28b40c17f5892"
        ));
        for value in [
            "commit a9f73c6d14e82b05f7c9134da6e28b40c17f5892",
            "sha256: a9f73c6d14e82b05f7c9134da6e28b40c17f5892",
        ] {
            assert!(safe_required_text(value), "rejected fixture {value:?}");
        }
    }

    #[test]
    fn wrapped_absolute_and_traversal_paths_are_rejected() {
        for value in [
            "`/Users/alice/private.rs`",
            "source=`../private.rs`",
            "path=\"file:///Users/alice/private.rs\"",
            "location='//server/share'",
            "checked [/etc/passwd]",
            "checked (src/../../private.rs)",
        ] {
            assert!(!safe_required_text(value), "accepted fixture {value:?}");
        }
    }

    #[test]
    fn angle_wrapped_unsafe_paths_are_rejected_without_rejecting_relational_prose() {
        for value in [
            "checked </etc/passwd>",
            "checked <../private.rs>",
            "checked <//server/share>",
            "checked <file:///Users/alice/private.rs>",
            "checked <C:/Users/alice/private.rs>",
            "path=</etc/passwd>",
        ] {
            assert!(!safe_required_text(value), "accepted fixture {value:?}");
        }
        for value in ["threshold < limit", "version >= minimum"] {
            assert!(safe_required_text(value), "rejected fixture {value:?}");
        }
    }

    #[test]
    fn lexical_candidate_boundaries_reject_unsafe_paths_at_public_policy_boundaries() {
        let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
        let reasons = [
            "checked!/etc/passwd".to_owned(),
            "checked?/etc/passwd".to_owned(),
            format!("commit=<{digest}>=/etc/passwd"),
            "checked!!/etc/passwd".to_owned(),
            "checked::/etc/passwd".to_owned(),
            "checked@@/etc/passwd".to_owned(),
            "checked||/etc/passwd".to_owned(),
            "checked=:/etc/passwd".to_owned(),
            "checked><!/etc/passwd".to_owned(),
            "safe=src/security/policy.rs|/etc/passwd".to_owned(),
            "checked!file:///Users/alice/private.rs".to_owned(),
            "checked?//server/share".to_owned(),
            "checked|C:/Users/alice/private.rs".to_owned(),
            "checked@../private.rs".to_owned(),
            "See(https://docs.example.com/../private)".to_owned(),
            "See(https://user@docs.example.com/security)".to_owned(),
            "See(https://docs.example.com/security?token=value)".to_owned(),
            "See(https://docs.example.com/security#fragment)".to_owned(),
            "See(https://docs.example.com/security)|/etc/passwd".to_owned(),
            "token=abc".to_owned(),
            "checked(/etc/passwd)".to_owned(),
            "path[/etc/passwd]".to_owned(),
            "note{/etc/passwd}".to_owned(),
            "checked</etc/passwd>".to_owned(),
            "checked'/etc/passwd'".to_owned(),
            "checked\"/etc/passwd\"".to_owned(),
            "checked`/etc/passwd`".to_owned(),
            "checked(file:///Users/alice/private.rs)".to_owned(),
            "checked[//server/share]".to_owned(),
            "checked{C:/Users/alice/private.rs}".to_owned(),
            "checked(src/../../private.rs)".to_owned(),
            format!("commit=<{digest}></etc/passwd>"),
            format!("commit=<{digest}>(../private.rs)"),
        ];

        for reason in reasons {
            let load_root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                load_root.path(),
                serde_json::json!({"version": 1, "entries": [{
                    "kind": "finding",
                    "fingerprintVersion": 1,
                    "fingerprint": "abcdef0123456789",
                    "category": "secret",
                    "state": "acceptedRisk",
                    "reason": reason.clone(),
                }]}),
            );
            assert_eq!(
                loaded.status(),
                &PolicyStatus::Invalid {
                    message: INVALID_POLICY_MESSAGE.to_owned()
                },
                "load accepted unsafe reason {reason:?}"
            );

            let update_root = tempfile::tempdir().unwrap();
            let mut unsafe_request = request(ReviewState::AcceptedRisk, "secret");
            unsafe_request.reason = reason.clone();
            let error = update_policy_decision(
                update_root.path(),
                &finding("secret"),
                &unsafe_request,
                now(),
            )
            .unwrap_err();
            assert_eq!(
                error.code,
                crate::findings::error::ErrorCode::ReviewInvalid,
                "update accepted unsafe reason {reason:?}"
            );
            assert_eq!(error.message, "The review request is invalid.");
            assert_eq!(error.detail, None);
        }
    }

    #[test]
    fn lexical_candidate_scan_preserves_safe_public_policy_reasons() {
        let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
        for reason in [
            "See(https://docs.example.com/security)".to_owned(),
            "See[https://docs.example.com/security]".to_owned(),
            "See<https://docs.example.com/security>".to_owned(),
            "See{https://docs.example.com/security}".to_owned(),
            "See'https://docs.example.com/security'".to_owned(),
            "See\"https://docs.example.com/security\"".to_owned(),
            "See`https://docs.example.com/security`".to_owned(),
            "See!?https://docs.example.com/security".to_owned(),
            "See(https://docs.example.com:8443/security)".to_owned(),
            format!("commit={digest}"),
            format!("commit=<{digest}>"),
            "See https://docs.example.com/security/production-feature-manifest".to_owned(),
            format!("sha256: {digest}"),
            "threshold < limit and version >= minimum".to_owned(),
            "comparison(a<b) and condition(x>y)".to_owned(),
            "production-feature-manifest".to_owned(),
            "checked(src/security/policy.rs)".to_owned(),
            "path[src/security/policy.rs]".to_owned(),
            "checked<refs/heads/main>".to_owned(),
            "ratio(1/2)".to_owned(),
        ] {
            let root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                root.path(),
                serde_json::json!({"version": 1, "entries": [{
                    "kind": "finding",
                    "fingerprintVersion": 1,
                    "fingerprint": "abcdef0123456789",
                    "category": "secret",
                    "state": "acceptedRisk",
                    "reason": reason.clone(),
                }]}),
            );
            assert!(
                matches!(loaded.status(), PolicyStatus::Valid { .. }),
                "load rejected safe reason {reason:?}"
            );

            let update_root = tempfile::tempdir().unwrap();
            let mut safe_request = request(ReviewState::AcceptedRisk, "secret");
            safe_request.reason = reason.clone();
            let review = update_policy_decision(
                update_root.path(),
                &finding("secret"),
                &safe_request,
                now(),
            )
            .unwrap_or_else(|error| panic!("update rejected safe reason {reason:?}: {error:?}"));
            assert_eq!(review.state, ReviewState::AcceptedRisk);
            assert_eq!(review.reason, reason);
            assert!(matches!(
                load_policy(update_root.path()).unwrap().status(),
                PolicyStatus::Valid { .. }
            ));
        }
    }

    #[test]
    fn public_policy_validation_is_linear_for_punctuation_heavy_near_cap_text() {
        let empty = serde_json::to_vec(&serde_json::json!({"version": 1, "entries": [{
            "kind": "finding",
            "fingerprintVersion": 1,
            "fingerprint": "abcdef0123456789",
            "category": "secret",
            "state": "acceptedRisk",
            "reason": "",
        }]}))
        .unwrap();
        let reason_len = MAX_POLICY_BYTES as usize - empty.len() - 1;
        let reason = "a!".repeat(reason_len / 2)
            + if reason_len.is_multiple_of(2) {
                ""
            } else {
                "a"
            };
        let work = portable_text_validation_work(&reason);
        assert!(
            work <= reason.len().saturating_mul(8).saturating_add(64),
            "validation performed {work} operations for {} bytes",
            reason.len()
        );

        let load_root = tempfile::tempdir().unwrap();
        let policy = serde_json::to_vec(&serde_json::json!({"version": 1, "entries": [{
            "kind": "finding",
            "fingerprintVersion": 1,
            "fingerprint": "abcdef0123456789",
            "category": "secret",
            "state": "acceptedRisk",
            "reason": reason,
        }]}))
        .unwrap();
        assert!(policy.len() <= MAX_POLICY_BYTES as usize);
        write_policy(load_root.path(), &policy);
        assert!(matches!(
            load_policy(load_root.path()).unwrap().status(),
            PolicyStatus::Valid { .. }
        ));

        let update_root = tempfile::tempdir().unwrap();
        let mut update = request(ReviewState::AcceptedRisk, "secret");
        update.reason = "a!".repeat((MAX_POLICY_BYTES as usize - 512) / 2);
        let saved = update_policy_decision(update_root.path(), &finding("secret"), &update, now())
            .expect("near-cap punctuation-heavy update remains responsive and valid");
        assert_eq!(saved.state, ReviewState::AcceptedRisk);
    }

    #[test]
    fn malformed_or_encoded_urls_are_rejected_at_public_policy_boundaries() {
        let unsafe_urls = [
            "See(https://:/etc/passwd)",
            "See(https://docs.example.com/%2e%2e/etc/passwd)",
            "See(https://docs.example.com/%2E%2e/etc/passwd)",
            "See(https://docs.example.com/security%2fprivate)",
            "See(https://docs.example.com/security%2Fprivate)",
            "See(https://docs.example.com/security%5cprivate)",
            "See(https://docs.example.com/security%5Cprivate)",
            "See(https://docs.example.com/security%)",
            "See(https://docs.example.com/security%2)",
            "See(https://docs.example.com:abc/security)",
            "See(https://docs.example.com:/security)",
            "See(https://./security)",
            "See(https://docs..example.com/security)",
            "See(https://-docs.example.com/security)",
            "See(https://docs-.example.com/security)",
            "See(https://user@docs.example.com/security)",
            "See(https://docs.example.com/security?mode=review)",
            "See(https://docs.example.com/security#review)",
        ];

        for reason in unsafe_urls {
            let load_root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                load_root.path(),
                serde_json::json!({"version": 1, "entries": [{
                    "kind": "finding",
                    "fingerprintVersion": 1,
                    "fingerprint": "abcdef0123456789",
                    "category": "secret",
                    "state": "acceptedRisk",
                    "reason": reason,
                }]}),
            );
            assert!(
                matches!(loaded.status(), PolicyStatus::Invalid { .. }),
                "load accepted unsafe URL {reason:?}"
            );

            let update_root = tempfile::tempdir().unwrap();
            let mut update = request(ReviewState::AcceptedRisk, "secret");
            update.reason = reason.into();
            let error =
                update_policy_decision(update_root.path(), &finding("secret"), &update, now())
                    .expect_err("unsafe URL must not be persisted");
            assert_eq!(error.code, crate::findings::error::ErrorCode::ReviewInvalid);
            assert_eq!(error.message, "The review request is invalid.");
            assert_eq!(error.detail, None);
        }
    }

    #[test]
    fn exact_valid_url_spans_preserve_safe_portable_text() {
        let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
        for reason in [
            "See(https://docs.example.com/security%20review)".to_owned(),
            "See(https://docs.example.com:8443/security)".to_owned(),
            "See!https://docs.example.com/security then src/security/policy.rs".to_owned(),
            "See(https://docs.example.com/security) and production-feature-manifest".to_owned(),
            "See(https://docs.example.com/security) threshold < limit".to_owned(),
            format!("See(https://docs.example.com/security) commit={digest}"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let loaded = load_json(
                root.path(),
                serde_json::json!({"version": 1, "entries": [{
                    "kind": "finding",
                    "fingerprintVersion": 1,
                    "fingerprint": "abcdef0123456789",
                    "category": "secret",
                    "state": "acceptedRisk",
                    "reason": reason,
                }]}),
            );
            assert!(
                matches!(loaded.status(), PolicyStatus::Valid { .. }),
                "load rejected safe URL text {reason:?}"
            );
        }
    }

    #[test]
    fn contextual_hash_assignments_are_allowed_before_generic_entropy_checks() {
        let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
        for label in ["commit", "sha256", "hash", "digest", "fingerprint"] {
            for value in [format!("{label}={digest}"), format!("{label}=<{digest}>")] {
                assert!(safe_required_text(&value), "rejected fixture {value:?}");
            }
        }
        assert!(!safe_required_text(digest));
    }

    #[test]
    fn windows_temp_handle_is_explicitly_closed_before_path_publication() {
        let source = include_str!("policy.rs");
        let windows_write = source
            .split("#[cfg(windows)]\nfn atomic_write_policy(")
            .nth(1)
            .expect("Windows policy writer remains present");
        let validation = windows_write
            .find("parse_and_validate(&persisted")
            .expect("the temp bytes are validated before publication");
        let close = windows_write
            .find("drop(temp);")
            .expect("the Windows temp handle has an explicit lifetime boundary");
        let publication = windows_write
            .find("windows_fs::durable_replace(")
            .expect("the Windows writer publishes through the durable helper");

        assert!(validation < close);
        assert!(close < publication);
    }

    #[test]
    fn safe_urls_and_conventional_kebab_identifiers_are_allowed() {
        for value in [
            "See https://docs.example.com/security/production-feature-manifest",
            "production-feature-manifest",
        ] {
            assert!(safe_required_text(value), "rejected fixture {value:?}");
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
                verdict: GateVerdict::Survives,
                evidence: "The input cannot be controlled externally".into(),
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
            serde_json::json!([
                {"gate":"intended","verdict":"unknown","evidence":"Not evaluated"},
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
    fn recovery_tamper_with_exact_candidate_restored_reports_committed_success() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let external = br#"{ "version": 1, "entries": [] }
"#;
        let mut modified_recovery = None;
        let mut candidate_bytes = None;

        let result = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterReplaceBeforeDirectorySync,
            |stage| {
                if stage == IoStage::AfterReplace {
                    candidate_bytes =
                        Some(fs::read(root.path().join(".oxaudit/policy.json")).unwrap());
                    let recovery = fs::read_dir(root.path().join(".oxaudit"))
                        .unwrap()
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .find(|path| {
                            path.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".policy.json.")
                                && path.extension().is_some_and(|extension| extension == "tmp")
                        })
                        .unwrap();
                    fs::write(&recovery, external).unwrap();
                    modified_recovery = Some(recovery);
                }
            },
        );

        assert_eq!(
            fs::read(root.path().join(".oxaudit/policy.json")).unwrap(),
            candidate_bytes.unwrap()
        );
        assert_eq!(fs::read(modified_recovery.unwrap()).unwrap(), external);
        let review = result.unwrap_or_else(|error| {
            panic!("verified committed candidate was reported as failure: {error:?}")
        });
        assert_eq!(review.state, ReviewState::FalsePositive);
        assert!(matches!(
            load_policy(root.path()).unwrap().status(),
            PolicyStatus::Valid { .. }
        ));
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
    fn project_root_swap_after_read_aborts_before_mutating_the_pinned_project() {
        let parent = tempfile::tempdir().unwrap();
        let project = parent.path().join("project");
        let held = parent.path().join("project-held");
        fs::create_dir(&project).unwrap();
        write_policy(&project, br#"{"version":1,"entries":[]}"#);
        let original = fs::read(project.join(".oxaudit/policy.json")).unwrap();

        let error = update_policy_decision_with_test_hook(
            &project,
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::BeforeTempCreate {
                    fs::rename(&project, &held).unwrap();
                    fs::create_dir(&project).unwrap();
                    fs::create_dir(project.join(".oxaudit")).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(
            fs::read(held.join(".oxaudit/policy.json")).unwrap(),
            original
        );
        assert!(!project.join(".oxaudit/policy.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn in_place_edit_after_preflight_wins_the_atomic_compare_exchange() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let external = br#"{ "version": 1, "entries": [] }
"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::AfterPolicyPreflight {
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
    fn replacement_after_preflight_wins_the_atomic_compare_exchange() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let displaced = root.path().join(".oxaudit/displaced-policy");
        let external = br#"{ "version": 1, "entries": [] }
"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::AfterPolicyPreflight {
                    fs::rename(&policy_path, &displaced).unwrap();
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
    fn late_edit_during_cas_mismatch_reversal_is_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let first_external = br#"{ "version": 1, "entries": [] }
"#;
        let latest_external = br#"{"version":999,"latest":"external"}"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| match stage {
                IoStage::AfterPolicyPreflight => {
                    fs::write(&policy_path, first_external).unwrap();
                }
                IoStage::BeforeRollbackExchange => {
                    fs::write(&policy_path, latest_external).unwrap();
                }
                _ => {}
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(policy_path).unwrap(), latest_external);
    }

    #[cfg(unix)]
    #[test]
    fn oversized_replacement_after_preflight_is_exchanged_back_unchanged() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let oversized = vec![b'x'; MAX_POLICY_BYTES as usize + 1];

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::AfterPolicyPreflight {
                    fs::write(&policy_path, &oversized).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(policy_path).unwrap(), oversized);
    }

    #[cfg(unix)]
    #[test]
    fn nonregular_replacement_after_preflight_is_exchanged_back_unchanged() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let displaced = root.path().join(".oxaudit/displaced-policy");
        let outside = root.path().join("outside.json");
        fs::write(&outside, b"outside").unwrap();

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::AfterPolicyPreflight {
                    fs::rename(&policy_path, &displaced).unwrap();
                    symlink(&outside, &policy_path).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert!(fs::symlink_metadata(&policy_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(policy_path).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn creation_after_missing_preflight_wins_no_clobber_publication() {
        let root = tempfile::tempdir().unwrap();
        let policy_path = root.path().join(".oxaudit/policy.json");
        let external = br#"{ "version": 1, "entries": [] }
"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::AfterPolicyPreflight {
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
    fn rollback_never_overwrites_in_place_or_replaced_external_final_bytes() {
        for replace_inode in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let original = br#"{"version":1,"entries":[]}"#;
            write_policy(root.path(), original);
            let policy_path = root.path().join(".oxaudit/policy.json");
            let displaced = root.path().join(".oxaudit/attempt-displaced");
            let external = br#"{ "version": 1, "entries": [] }
"#;

            let error = update_policy_decision_with_test_hook(
                root.path(),
                &finding("secret"),
                &request(ReviewState::FalsePositive, "secret"),
                now(),
                WriteFailure::AfterReplaceBeforeDirectorySync,
                |stage| {
                    if stage == IoStage::AfterReplace {
                        if replace_inode {
                            fs::rename(&policy_path, &displaced).unwrap();
                        }
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
            let recovery = fs::read_dir(root.path().join(".oxaudit"))
                .unwrap()
                .filter_map(Result::ok)
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".policy.json.")
                        && entry.path().extension().is_some_and(|value| value == "tmp")
                })
                .unwrap();
            assert_eq!(fs::read(recovery.path()).unwrap(), original);
        }
    }

    #[cfg(unix)]
    #[test]
    fn late_in_place_edit_immediately_before_rollback_exchange_wins() {
        let root = tempfile::tempdir().unwrap();
        let original = br#"{"version":1,"entries":[]}"#;
        write_policy(root.path(), original);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let external = br#"{ "version": 1, "entries": [] }
"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterReplaceBeforeDirectorySync,
            |stage| {
                if stage == IoStage::BeforeRollbackExchange {
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
        let recovery = fs::read_dir(root.path().join(".oxaudit"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".policy.json.")
                    && entry.path().extension().is_some_and(|value| value == "tmp")
            })
            .unwrap();
        assert_eq!(fs::read(recovery.path()).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn late_edit_after_undo_recheck_is_compensated_back_to_policy() {
        for replace_inode in [false, true] {
            let root = tempfile::tempdir().unwrap();
            write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
            let policy_path = root.path().join(".oxaudit/policy.json");
            let held_late_policy = root.path().join(".oxaudit/late-policy-held");
            let recovery_tamper = br#"{ "version": 1, "entries": [] }
"#;
            let latest = br#"{"version":999,"latest":"authoritative"}"#;
            let mut candidate = None;
            let mut recovery_path = None;

            let result = update_policy_decision_with_test_hook(
                root.path(),
                &finding("secret"),
                &request(ReviewState::FalsePositive, "secret"),
                now(),
                WriteFailure::AfterReplaceBeforeDirectorySync,
                |stage| match stage {
                    IoStage::AfterReplace => {
                        candidate = Some(fs::read(&policy_path).unwrap());
                        let recovery = fs::read_dir(root.path().join(".oxaudit"))
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
                        fs::write(&recovery, recovery_tamper).unwrap();
                        recovery_path = Some(recovery);
                    }
                    IoStage::AfterRollbackRecheckBeforeUndo => {
                        if replace_inode {
                            fs::rename(&policy_path, &held_late_policy).unwrap();
                        }
                        fs::write(&policy_path, latest).unwrap();
                    }
                    _ => {}
                },
            );

            let error = result.unwrap_err();
            assert_eq!(
                error.code,
                crate::findings::error::ErrorCode::PolicyWriteFailed
            );
            assert_eq!(fs::read(&policy_path).unwrap(), latest);
            assert_eq!(
                fs::read(recovery_path.unwrap()).unwrap(),
                candidate.unwrap()
            );
            if replace_inode {
                assert_eq!(fs::read(&held_late_policy).unwrap(), recovery_tamper);
            }
            assert!(matches!(
                load_policy(root.path()).unwrap().status(),
                PolicyStatus::Invalid { .. }
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn late_edit_before_missing_policy_rollback_is_not_unlinked() {
        for replace_inode in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let policy_path = root.path().join(".oxaudit/policy.json");
            let displaced = root.path().join(".oxaudit/late-attempt");
            let external = br#"{"version":999,"latest":"external"}"#;

            let error = update_policy_decision_with_test_hook(
                root.path(),
                &finding("secret"),
                &request(ReviewState::FalsePositive, "secret"),
                now(),
                WriteFailure::AfterReplaceBeforeDirectorySync,
                |stage| {
                    if stage == IoStage::BeforeRollbackExchange {
                        if replace_inode {
                            fs::rename(&policy_path, &displaced).unwrap();
                        }
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
            let mut recovery_before_rollback = None;
            if had_policy {
                write_policy(root.path(), original);
            }

            let error = update_policy_decision_with_test_hook(
                root.path(),
                &finding("secret"),
                &request(ReviewState::FalsePositive, "secret"),
                now(),
                WriteFailure::AfterReplaceBeforeDirectorySync,
                |stage| {
                    if had_policy && stage == IoStage::AfterReplace {
                        recovery_before_rollback = fs::read_dir(root.path().join(".oxaudit"))
                            .unwrap()
                            .filter_map(Result::ok)
                            .find(|entry| {
                                entry
                                    .file_name()
                                    .to_string_lossy()
                                    .starts_with(".policy.json.")
                                    && entry.path().extension().is_some_and(|value| value == "tmp")
                            })
                            .map(|entry| fs::read(entry.path()).unwrap());
                    }
                },
            )
            .unwrap_err();
            assert_eq!(
                error.code,
                crate::findings::error::ErrorCode::PolicyWriteFailed
            );

            let policy_path = root.path().join(".oxaudit/policy.json");
            if had_policy {
                assert_eq!(fs::read(policy_path).unwrap(), original);
                assert_eq!(recovery_before_rollback.unwrap(), original);
                assert!(matches!(
                    load_policy(root.path()).unwrap().status(),
                    PolicyStatus::Valid { .. }
                ));
            } else {
                assert!(!policy_path.exists());
                assert_eq!(
                    load_policy(root.path()).unwrap().status(),
                    &PolicyStatus::Missing
                );
            }
            assert!(!fs::read_dir(root.path().join(".oxaudit"))
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".policy.json.")));
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
