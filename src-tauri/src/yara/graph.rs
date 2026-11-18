//! The canonical graph and the stored rows for a YARA scan: one file artifact
//! per matched file, one `SignatureMatch` observation per rule match, and
//! one `BinaryMatch` evidence per kept string match.

use oxaudit_application::ObservationRecord;
use oxaudit_domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactLocation, BinaryMatchEvidence, Evidence,
    EvidenceId, EvidenceRecord, Observation, ObservationId, ObservationKind, RunId,
};
use oxaudit_yara::{MetaValue, RuleMatch};
use sha2::{Digest, Sha256};

use super::scan::FileMatches;
use super::{YaraMatchRow, YaraStringRow, MAX_MATCH_ROWS};

pub(crate) const DETECTOR_ID: &str = "oxaudit-yara";

pub(crate) struct Built {
    pub rows: Vec<YaraMatchRow>,
    pub artifacts: Vec<Artifact>,
    pub observations: Vec<ObservationRecord>,
    /// Rule matches beyond the row cap; counted, not kept.
    pub dropped: u64,
}

fn severity_label(severity: oxaudit_domain::Severity) -> &'static str {
    use oxaudit_domain::Severity::*;
    match severity {
        Info => "info",
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    }
}

fn meta_json(value: &MetaValue) -> serde_json::Value {
    match value {
        MetaValue::String(s) => serde_json::Value::String(s.clone()),
        MetaValue::Integer(i) => serde_json::json!(i),
        MetaValue::Float(f) => serde_json::json!(f),
        MetaValue::Bool(b) => serde_json::Value::Bool(*b),
        MetaValue::Bytes(b) => serde_json::Value::String(hex::encode(b)),
    }
}

/// The pack and in-pack path of a namespace built as `<pack>/<path>`.
fn split_namespace(namespace: &str) -> (&str, &str) {
    namespace.split_once('/').unwrap_or(("", namespace))
}

/// `<pack id>/<namespace>:<rule>`: with the compile-time namespace already
/// `<pack id>/<path>`, that is `<namespace>:<rule>`.
pub(crate) fn rule_id(m: &RuleMatch) -> String {
    format!("{}:{}", m.namespace, m.rule)
}

pub(crate) fn build(
    run_id: &RunId,
    matched: &[FileMatches],
    detector_version: &str,
) -> Result<Built, String> {
    let mut built = Built {
        rows: Vec::new(),
        artifacts: Vec::new(),
        observations: Vec::new(),
        dropped: 0,
    };
    for file in matched {
        let mut artifact_id: Option<ArtifactId> = None;
        for m in &file.matches {
            if built.rows.len() >= MAX_MATCH_ROWS {
                built.dropped += 1;
                continue;
            }
            let artifact_id = match &artifact_id {
                Some(id) => id.clone(),
                None => {
                    let id = ArtifactId::parse(format!(
                        "artifact_{}",
                        hex::encode(Sha256::digest(format!("{run_id}\0{}", file.rel).as_bytes()))
                    ))
                    .map_err(|error| error.to_string())?;
                    built.artifacts.push(Artifact {
                        id: id.clone(),
                        kind: ArtifactKind::File,
                        location: ArtifactLocation {
                            normalized_path: file.rel.clone(),
                            canonical_path: Some(file.abs.to_string_lossy().into_owned()),
                            parent_id: None,
                        },
                        size_bytes: file.size,
                        media_type: None,
                        content_sha256: Some(file.sha256.clone()),
                    });
                    artifact_id = Some(id.clone());
                    id
                }
            };
            let (pack, in_pack) = split_namespace(&m.namespace);
            let id = rule_id(m);
            let mut evidence: Vec<EvidenceRecord> = m
                .strings
                .iter()
                .map(|s| EvidenceRecord {
                    id: EvidenceId::new(),
                    evidence: Evidence::BinaryMatch(BinaryMatchEvidence {
                        artifact_id: artifact_id.clone(),
                        offset: Some(s.offset),
                        section: None,
                        matcher_id: s.identifier.clone(),
                        encoding: "hex".into(),
                        captured_value: Some(s.excerpt_hex.clone()),
                    }),
                })
                .collect();
            if evidence.is_empty() {
                // A rule that matches on file properties alone (size, header
                // fields) has no string to point at; the evidence says so.
                evidence.push(EvidenceRecord {
                    id: EvidenceId::new(),
                    evidence: Evidence::BinaryMatch(BinaryMatchEvidence {
                        artifact_id: artifact_id.clone(),
                        offset: None,
                        section: None,
                        matcher_id: "condition".into(),
                        encoding: "none".into(),
                        captured_value: None,
                    }),
                });
            }
            built.observations.push(ObservationRecord {
                observation: Observation {
                    id: ObservationId::new(),
                    run_id: run_id.clone(),
                    artifact_id,
                    kind: ObservationKind::SignatureMatch,
                    detector_id: DETECTOR_ID.into(),
                    detector_version: detector_version.into(),
                    rule_id: Some(id.clone()),
                    title: m.rule.clone(),
                    summary: format!(
                        "YARA rule {} from {pack} matched {} ({} string match{})",
                        m.rule,
                        file.rel,
                        m.strings.len() as u64 + m.strings_truncated,
                        if m.strings.len() as u64 + m.strings_truncated == 1 {
                            ""
                        } else {
                            "es"
                        }
                    ),
                    evidence_ids: evidence.iter().map(|record| record.id.clone()).collect(),
                },
                evidence,
            });
            built.rows.push(YaraMatchRow {
                id: format!("match-{}", built.rows.len() + 1),
                path: file.rel.clone(),
                file_path: file.rel.clone(),
                sha256: file.sha256.clone(),
                rule: m.rule.clone(),
                namespace: in_pack.to_owned(),
                pack: pack.to_owned(),
                rule_id: id,
                tags: m.tags.clone(),
                severity: severity_label(m.severity).to_owned(),
                meta: m
                    .meta
                    .iter()
                    .map(|(k, v)| (k.clone(), meta_json(v)))
                    .collect(),
                strings: m
                    .strings
                    .iter()
                    .map(|s| YaraStringRow {
                        identifier: s.identifier.clone(),
                        offset: s.offset,
                        length: s.length,
                        excerpt_hex: s.excerpt_hex.clone(),
                    })
                    .collect(),
                strings_truncated: m.strings_truncated,
            });
        }
    }
    Ok(built)
}
