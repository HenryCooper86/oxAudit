//! Signature packs: user-imported YARA rules and Nuclei templates.
//!
//! oxAudit ships the engines and no third-party content. A pack is a set of
//! files of one kind imported from a file, a folder, or a `.zip`, copied
//! under `<data dir>/sigpacks/<kind>/<id>/` with a SHA-256 manifest, and
//! recorded in the `signature_packs` table of the rule-pack database. Every
//! scan re-verifies the files against the manifest, and the manifest against
//! the content hash stored in the database; a pack that fails is skipped with
//! its reason, never silently applied.

mod license;
mod source;
mod store;

use serde::{Deserialize, Serialize};

#[cfg(feature = "yara")]
pub use store::ResolvedSigPacks;
pub use store::{InstalledSigPack, PackMetadata, PackPreview, SigPackStore, SigPacksState};

/// The two kinds of signature pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PackKind {
    Yara,
    Nuclei,
}

impl PackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yara => "yara",
            Self::Nuclei => "nuclei",
        }
    }

    /// File extensions accepted as rule files, without the dot.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Yara => &["yar", "yara"],
            Self::Nuclei => &["yaml", "yml"],
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "yara" => Ok(Self::Yara),
            "nuclei" => Ok(Self::Nuclei),
            other => Err(format!(
                "unknown signature pack kind {other:?}; expected yara or nuclei"
            )),
        }
    }
}

/// A rule file or rule that was left out, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackSkip {
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
}

#[cfg(feature = "yara")]
pub use source::{collect as collect_source, PackFile};
pub use store::validate_pack;

#[cfg(all(test, feature = "yara"))]
mod tests;
