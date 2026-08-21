use serde::{Deserialize, Serialize};

use crate::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreationMethod {
    IndependentlyDerived,
    Authored,
    GeneratedFromPublicSpecification,
    ImportedExternalReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub authors: Vec<String>,
    pub source: String,
    pub license: String,
    pub creation_method: CreationMethod,
    pub content_sha256: String,
}

impl Provenance {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.authors.is_empty() || self.authors.iter().any(|author| author.trim().is_empty()) {
            return Err(DomainError::MissingProvenance { field: "authors" });
        }
        for (field, value) in [
            ("source", self.source.as_str()),
            ("license", self.license.as_str()),
            ("contentSha256", self.content_sha256.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(DomainError::MissingProvenance { field });
            }
        }
        if self.content_sha256.len() != 64
            || !self
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DomainError::MissingProvenance {
                field: "contentSha256 (64 hexadecimal characters)",
            });
        }
        Ok(())
    }
}
