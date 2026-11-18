//! The YARA scan: request and result shapes, the file walk, the parallel
//! scan, and the canonical graph. `commands/yara.rs` wires it to a run
//! lifecycle; nothing here touches Tauri or the findings database.
//!
//! The types are always compiled so the command surface is identical in
//! every build. The engine itself needs the `yara` feature; without it the
//! `scan_yara` command fails with an explicit error and never returns an
//! empty result.

// Limits and helpers are only used by the engine, which needs the feature.
#![cfg_attr(not(feature = "yara"), allow(dead_code))]

#[cfg(feature = "yara")]
pub(crate) mod graph;
#[cfg(feature = "yara")]
pub(crate) mod scan;

use serde::{Deserialize, Serialize};

/// Largest `maxFileSizeMb` accepted.
pub const MAX_FILE_SIZE_MB_LIMIT: u32 = 4096;
pub const DEFAULT_MAX_FILE_SIZE_MB: u32 = 64;
/// Files beyond this are reported, not scanned, and make the run Incomplete.
pub const MAX_FILES: usize = 1_000_000;
/// Stored match rows; the remainder is counted and the run is Incomplete.
pub const MAX_MATCH_ROWS: usize = 100_000;
/// Stored skipped-file rows; the remainder is counted.
pub const MAX_SKIPPED_ROWS: usize = 100_000;
/// Stored rule-source skip rows; the remainder is counted.
pub const MAX_RULE_SKIP_ROWS: usize = 500;
/// Pack id used for one-off rule paths that are not installed.
pub const ADHOC_PACK_ID: &str = "adhoc";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraScanRequest {
    /// File or folder to scan.
    pub path: String,
    /// Installed YARA packs to apply. `None` means every enabled pack.
    #[serde(default)]
    pub pack_ids: Option<Vec<String>>,
    /// One-off rule files or folders that are not installed.
    #[serde(default)]
    pub extra_rule_paths: Vec<String>,
    /// Files larger than this are listed as skipped. Default 64.
    #[serde(default)]
    pub max_file_size_mb: Option<u32>,
    #[serde(default)]
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraSkippedFile {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraPackInfo {
    pub id: String,
    pub name: String,
    pub license: String,
    pub content_sha256: String,
    pub rule_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraRuleSkip {
    pub pack: String,
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraStringRow {
    pub identifier: String,
    pub offset: u64,
    pub length: u64,
    pub excerpt_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraMatchRow {
    /// Unique within the run; the paged-results key.
    pub id: String,
    /// Path relative to the scan target, forward slashes.
    pub path: String,
    /// The same value as `path`; the key the paged index sorts and filters by.
    pub file_path: String,
    pub sha256: String,
    pub rule: String,
    /// The rule file's path inside its pack.
    pub namespace: String,
    pub pack: String,
    /// `<pack>/<namespace>:<rule>`, also the observation's rule id.
    pub rule_id: String,
    pub tags: Vec<String>,
    /// `info`, `low`, `medium`, `high` or `critical`.
    pub severity: String,
    pub meta: Vec<(String, serde_json::Value)>,
    pub strings: Vec<YaraStringRow>,
    pub strings_truncated: u64,
}

/// The stored and returned result of a YARA scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraScanResult {
    pub run_id: String,
    pub target: String,
    /// `completed` or `incomplete`. A scan that was cancelled or failed
    /// returns an error instead of a result.
    pub state: String,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub matches: Vec<YaraMatchRow>,
    /// Match rows beyond the stored cap; counted, not kept.
    pub matches_dropped: u64,
    pub skipped: Vec<YaraSkippedFile>,
    /// Skipped files beyond the stored cap.
    pub skipped_dropped: u64,
    pub packs: Vec<YaraPackInfo>,
    pub rules_compiled: usize,
    pub rules_skipped: Vec<YaraRuleSkip>,
    pub rules_skipped_total: usize,
    /// Why the run is incomplete, or other limits worth knowing; empty for
    /// a fully covered scan.
    pub notes: Vec<String>,
    pub duration_ms: u64,
}

/// A request that fails its own bounds before any work starts.
pub fn max_file_bytes(request: &YaraScanRequest) -> Result<u64, String> {
    let mb = request.max_file_size_mb.unwrap_or(DEFAULT_MAX_FILE_SIZE_MB);
    if mb == 0 || mb > MAX_FILE_SIZE_MB_LIMIT {
        return Err(format!(
            "maxFileSizeMb must be between 1 and {MAX_FILE_SIZE_MB_LIMIT}"
        ));
    }
    Ok(u64::from(mb) * 1024 * 1024)
}
