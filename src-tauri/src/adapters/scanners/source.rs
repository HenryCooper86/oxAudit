use oxaudit_application::ObservationRecord;
use oxaudit_domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactLocation, Evidence, EvidenceId, EvidenceRecord,
    FileLocationEvidence, Observation, ObservationId, ObservationKind, RedactedSecretEvidence,
    RedactedValue, RunId,
};
use sha2::{Digest, Sha256};

use crate::fs_utils::SourceFile;
use crate::models::Finding;

pub fn source_artifact(run_id: &RunId, file: &SourceFile) -> Result<Artifact, String> {
    let relative = file
        .project_relative_path
        .to_string_lossy()
        .replace('\\', "/");
    let identity = format!(
        "artifact_{:x}",
        Sha256::digest(format!("{}\0{}", run_id, relative).as_bytes())
    );
    let size_bytes = file
        .canonical_path
        .metadata()
        .map_err(|error| error.to_string())?
        .len();
    Ok(Artifact {
        id: ArtifactId::parse(identity).map_err(|error| error.to_string())?,
        kind: ArtifactKind::SourceFile,
        location: ArtifactLocation {
            normalized_path: relative,
            canonical_path: Some(file.canonical_path.to_string_lossy().into_owned()),
            parent_id: None,
        },
        size_bytes,
        media_type: Some("text/plain".into()),
        content_sha256: None,
    })
}

pub fn source_observation(
    run_id: &RunId,
    artifact: &Artifact,
    finding: &Finding,
) -> Result<ObservationRecord, String> {
    let observation_id =
        ObservationId::parse(finding.id.clone()).unwrap_or_else(|_| ObservationId::new());
    let evidence_id = EvidenceId::new();
    let location = FileLocationEvidence {
        artifact_id: artifact.id.clone(),
        normalized_path: artifact.location.normalized_path.clone(),
        start_line: u32::try_from(finding.line).ok(),
        start_column: u32::try_from(finding.column).ok(),
        end_line: u32::try_from(finding.line).ok(),
        end_column: None,
        context_sha256: Some(format!("{:x}", Sha256::digest(finding.context.as_bytes()))),
    };
    let (kind, evidence) = if finding.category == "secret" {
        let correlation = format!(
            "{:x}",
            Sha256::digest(
                format!("{}\0{}\0{}", run_id, finding.fingerprint, finding.id).as_bytes()
            )
        );
        let redacted = RedactedValue::secret("credential material", correlation)
            .map_err(|error| error.to_string())?;
        (
            ObservationKind::SecretCandidate,
            Evidence::RedactedSecret(RedactedSecretEvidence {
                artifact_id: artifact.id.clone(),
                rule_id: finding.rule_id.clone(),
                location,
                value: redacted,
            }),
        )
    } else {
        (
            ObservationKind::SourceWeakness,
            Evidence::FileLocation(location),
        )
    };
    Ok(ObservationRecord {
        observation: Observation {
            id: observation_id,
            run_id: run_id.clone(),
            artifact_id: artifact.id.clone(),
            kind,
            detector_id: "oxaudit.native.source".into(),
            detector_version: env!("CARGO_PKG_VERSION").into(),
            rule_id: Some(finding.rule_id.clone()),
            title: finding.title.clone(),
            summary: finding.description.clone(),
            evidence_ids: vec![evidence_id.clone()],
        },
        evidence: vec![EvidenceRecord {
            id: evidence_id,
            evidence,
        }],
    })
}
