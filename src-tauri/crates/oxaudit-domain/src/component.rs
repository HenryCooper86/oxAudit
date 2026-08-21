use serde::{Deserialize, Serialize};

use crate::{ArtifactId, ComponentId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMethod {
    DeclaredManifest,
    PackageMetadata,
    Filename,
    CharacteristicString,
    ByteSignature,
    ImportedSbom,
    ExternalTool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentIdentity {
    pub method: IdentityMethod,
    pub value: String,
    pub confidence: f32,
    pub source_artifact_id: ArtifactId,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub id: ComponentId,
    pub name: String,
    pub version: Option<String>,
    pub supplier: Option<String>,
    pub ecosystem: Option<String>,
    pub purl: Option<String>,
    pub cpes: Vec<String>,
    pub aliases: Vec<String>,
    pub identities: Vec<ComponentIdentity>,
}
