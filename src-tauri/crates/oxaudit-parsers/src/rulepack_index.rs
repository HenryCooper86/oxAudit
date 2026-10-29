//! The rule-pack feed index: the JSON a feed serves listing its packs.
//!
//! Parsed here, apart from the fetching and installing in the main crate, so
//! the parser of this untrusted download can be fuzzed on its own.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPack {
    pub id: String,
    pub version: String,
    pub file: String,
    pub sha256: String,
}

/// Parse and validate the feed index. Anything malformed names the entry.
pub fn parse_index(bytes: &[u8]) -> Result<Vec<FeedPack>, String> {
    let index: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("feed index is not JSON: {error}"))?;
    if index
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err("feed index schemaVersion must be 1".into());
    }
    let packs = index
        .get("packs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "feed index has no packs array".to_string())?;
    let mut seen = std::collections::BTreeSet::new();
    let mut parsed = Vec::new();
    for entry in packs {
        let field = |name: &str| -> Result<String, String> {
            entry
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("feed entry is missing {name}"))
        };
        let pack = FeedPack {
            id: field("id")?,
            version: field("version")?,
            file: field("file")?,
            sha256: field("sha256")?,
        };
        if pack.sha256.len() != 64 || !pack.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "feed entry {} declares a malformed sha256",
                pack.id
            ));
        }
        if !seen.insert(pack.id.clone()) {
            return Err(format!("feed index lists {} twice", pack.id));
        }
        parsed.push(pack);
    }
    Ok(parsed)
}
