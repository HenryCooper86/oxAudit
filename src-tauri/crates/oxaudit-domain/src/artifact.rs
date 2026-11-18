use serde::{Deserialize, Serialize};

use crate::ArtifactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    SourceFile,
    Lockfile,
    Binary,
    Archive,
    ArchiveMember,
    ContainerLayer,
    Sbom,
    Report,
    /// Any scanned file, regardless of content type (YARA and template scans).
    File,
    /// A live network target (URL, host or host:port) named by the user.
    NetworkTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactLocation {
    pub normalized_path: String,
    pub canonical_path: Option<String>,
    pub parent_id: Option<ArtifactId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub id: ArtifactId,
    pub kind: ArtifactKind,
    pub location: ArtifactLocation,
    pub size_bytes: u64,
    pub media_type: Option<String>,
    pub content_sha256: Option<String>,
}
