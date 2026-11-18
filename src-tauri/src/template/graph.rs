//! The canonical graph and the stored rows for a Template scan: one artifact
//! per matched file (`File`) or live target (`NetworkTarget`), one
//! `TemplateMatch` observation per template match, and one `FileLocation`
//! evidence per kept matched line, or one `NetworkExchange` evidence for a
//! live match.

use std::collections::BTreeMap;

use oxaudit_application::ObservationRecord;
use oxaudit_domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactLocation, Evidence, EvidenceId, EvidenceRecord,
    FileLocationEvidence, NetworkExchangeEvidence, Observation, ObservationId, ObservationKind,
    RunId,
};
use sha2::{Digest, Sha256};

use super::exec::{FileSubject, RawMatch, Subject, TargetSubject};
use super::select::Selected;
use super::{
    severity_label, TemplateClassification, TemplateExchange, TemplateLineRow, TemplateMatchRow,
    MAX_EXTRACTED_CHARS, MAX_EXTRACTED_VALUES, MAX_LINES_PER_ROW, MAX_LINE_CHARS, MAX_MATCH_ROWS,
};

pub(crate) const DETECTOR_ID: &str = "oxaudit-nuclei";

pub(crate) struct Built {
    pub rows: Vec<TemplateMatchRow>,
    pub artifacts: Vec<Artifact>,
    pub observations: Vec<ObservationRecord>,
    /// Matches beyond the row cap; counted, not kept.
    pub dropped: u64,
}

fn cap_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Extracted values bounded the same way in the row and the evidence.
fn capped_extracted(extracted: &[(String, Vec<String>)]) -> Vec<(String, Vec<String>)> {
    extracted
        .iter()
        .map(|(name, values)| {
            (
                name.clone(),
                values
                    .iter()
                    .take(MAX_EXTRACTED_VALUES)
                    .map(|value| cap_chars(value, MAX_EXTRACTED_CHARS))
                    .collect(),
            )
        })
        .collect()
}

/// The projection row for one match. Values that need masking were masked
/// by the executor; this only bounds sizes.
pub(crate) fn row(selected: &Selected, raw: &RawMatch, id: String) -> TemplateMatchRow {
    let template = &selected.template;
    let info = &template.info;
    let found = &raw.found;
    let (file_path, exchange) = match &raw.subject {
        Subject::File(file) => (Some(file.rel.clone()), None),
        Subject::Target(target) => (
            None,
            target.exchange.as_ref().map(|exchange| TemplateExchange {
                protocol: exchange.protocol.clone(),
                target: exchange.target.clone(),
                request: exchange.request.clone(),
                response_excerpt: exchange.response_excerpt.clone(),
                response_truncated: exchange.response_truncated,
            }),
        ),
    };
    TemplateMatchRow {
        id,
        template_id: template.id.clone(),
        rule_id: selected.rule_id.clone(),
        name: info.name.clone(),
        severity: severity_label(found.severity).to_owned(),
        tags: info.tags.clone(),
        pack: selected.pack.clone(),
        protocol: found.protocol.as_str().to_owned(),
        matched_at: found.matched_at.clone(),
        file_path,
        lines: found
            .lines
            .iter()
            .take(MAX_LINES_PER_ROW)
            .map(|line| TemplateLineRow {
                line: u32::try_from(line.line).unwrap_or(u32::MAX),
                start_column: u32::try_from(line.start_column).unwrap_or(u32::MAX),
                end_column: u32::try_from(line.end_column).unwrap_or(u32::MAX),
                text: cap_chars(&line.text, MAX_LINE_CHARS),
            })
            .collect(),
        matcher_names: found.matcher_names.clone(),
        extracted: capped_extracted(&found.extracted),
        classification: TemplateClassification {
            cve_id: info.classification.cve_id.clone(),
            cwe_id: info.classification.cwe_id.clone(),
            cvss_score: info.classification.cvss_score,
        },
        description: info.description.clone(),
        reference: info.reference.clone(),
        remediation: info.remediation.clone(),
        exchange,
    }
}

fn artifact_id(run_id: &RunId, key: &str) -> Result<ArtifactId, String> {
    ArtifactId::parse(format!(
        "artifact_{}",
        hex::encode(Sha256::digest(format!("{run_id}\0{key}").as_bytes()))
    ))
    .map_err(|error| error.to_string())
}

/// Evidence for a file match: one location per kept matched line, or the
/// file itself when the template matched on the file as a whole.
fn file_evidence(
    artifact_id: &ArtifactId,
    file: &FileSubject,
    raw: &RawMatch,
) -> Vec<EvidenceRecord> {
    let location = |line: Option<(u32, u32, u32)>| EvidenceRecord {
        id: EvidenceId::new(),
        evidence: Evidence::FileLocation(FileLocationEvidence {
            artifact_id: artifact_id.clone(),
            normalized_path: file.rel.clone(),
            start_line: line.map(|l| l.0),
            start_column: line.map(|l| l.1),
            end_line: line.map(|l| l.0),
            end_column: line.map(|l| l.2),
            context_sha256: None,
        }),
    };
    let mut evidence: Vec<EvidenceRecord> = raw
        .found
        .lines
        .iter()
        .take(MAX_LINES_PER_ROW)
        .map(|line| {
            location(Some((
                u32::try_from(line.line).unwrap_or(u32::MAX),
                u32::try_from(line.start_column).unwrap_or(u32::MAX),
                u32::try_from(line.end_column).unwrap_or(u32::MAX),
            )))
        })
        .collect();
    if evidence.is_empty() {
        // A template that matched on the file as a whole (a size or DSL
        // matcher) has no line to point at; the evidence names the file.
        evidence.push(location(None));
    }
    evidence
}

/// Evidence for a live match: the exchange that matched, attached to the
/// target's artifact. Matcher names and extracted values come from the
/// (already masked) match so the evidence never holds more than the row.
fn target_evidence(
    artifact_id: &ArtifactId,
    target: &TargetSubject,
    raw: &RawMatch,
) -> Vec<EvidenceRecord> {
    let exchange = match &target.exchange {
        Some(exchange) => NetworkExchangeEvidence {
            artifact_id: artifact_id.clone(),
            matcher_names: raw.found.matcher_names.clone(),
            extracted: capped_extracted(&raw.found.extracted),
            ..exchange.clone()
        },
        None => NetworkExchangeEvidence {
            artifact_id: artifact_id.clone(),
            protocol: raw.found.protocol.as_str().to_owned(),
            target: target.target.clone(),
            request: String::new(),
            response_excerpt: String::new(),
            response_truncated: false,
            matcher_names: raw.found.matcher_names.clone(),
            extracted: capped_extracted(&raw.found.extracted),
        },
    };
    vec![EvidenceRecord {
        id: EvidenceId::new(),
        evidence: Evidence::NetworkExchange(exchange),
    }]
}

pub(crate) fn build(
    run_id: &RunId,
    selected: &[Selected],
    matches: &[RawMatch],
    detector_version: &str,
) -> Result<Built, String> {
    let mut built = Built {
        rows: Vec::new(),
        artifacts: Vec::new(),
        observations: Vec::new(),
        dropped: 0,
    };
    let mut artifact_ids: BTreeMap<String, ArtifactId> = BTreeMap::new();
    for raw in matches {
        if built.rows.len() >= MAX_MATCH_ROWS {
            built.dropped += 1;
            continue;
        }
        let template = &selected[raw.template];
        // One artifact per matched file or live target, keyed so a file and
        // a target can never share one.
        let (key, place) = match &raw.subject {
            Subject::File(file) => (format!("file\0{}", file.rel), file.rel.clone()),
            Subject::Target(target) => {
                (format!("target\0{}", target.target), target.target.clone())
            }
        };
        let artifact_id = match artifact_ids.get(&key) {
            Some(id) => id.clone(),
            None => {
                let id = match &raw.subject {
                    // Unchanged from before live targets, so file artifact
                    // ids stay stable.
                    Subject::File(file) => artifact_id(run_id, &file.rel)?,
                    Subject::Target(_) => artifact_id(run_id, &key)?,
                };
                built.artifacts.push(match &raw.subject {
                    Subject::File(file) => Artifact {
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
                    },
                    Subject::Target(target) => Artifact {
                        id: id.clone(),
                        kind: ArtifactKind::NetworkTarget,
                        location: ArtifactLocation {
                            normalized_path: target.target.clone(),
                            canonical_path: None,
                            parent_id: None,
                        },
                        size_bytes: 0,
                        media_type: None,
                        content_sha256: None,
                    },
                });
                artifact_ids.insert(key, id.clone());
                id
            }
        };
        let evidence = match &raw.subject {
            Subject::File(file) => file_evidence(&artifact_id, file, raw),
            Subject::Target(target) => target_evidence(&artifact_id, target, raw),
        };
        let row = row(template, raw, format!("match-{}", built.rows.len() + 1));
        built.observations.push(ObservationRecord {
            observation: Observation {
                id: ObservationId::new(),
                run_id: run_id.clone(),
                artifact_id: artifact_id.clone(),
                kind: ObservationKind::TemplateMatch,
                detector_id: DETECTOR_ID.into(),
                detector_version: detector_version.into(),
                rule_id: Some(template.rule_id.clone()),
                title: row.name.clone(),
                summary: match &raw.subject {
                    Subject::File(_) => format!(
                        "Template {} from {} matched {} ({} location{})",
                        row.template_id,
                        row.pack,
                        place,
                        evidence.len(),
                        if evidence.len() == 1 { "" } else { "s" }
                    ),
                    Subject::Target(_) => format!(
                        "Template {} from {} matched live target {} over {}",
                        row.template_id, row.pack, place, row.protocol
                    ),
                },
                evidence_ids: evidence.iter().map(|record| record.id.clone()).collect(),
            },
            evidence,
        });
        built.rows.push(row);
    }
    Ok(built)
}
