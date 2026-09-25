//! Fetching rule packs from a feed.
//!
//! A feed is an index URL serving JSON: one entry per pack, pointing at a zip
//! that carries `pack.toml` and its fixture files together — fixtures are
//! part of a pack's proof, so they travel with it. Every download is
//! verified against the sha256 the index declares, and every pack goes
//! through the same validation a hand-installed pack does: parse, validate,
//! fixture hashes, and a compile proof before it is stored. A pack the feed
//! serves at the already-installed version is skipped, and an update never
//! silently re-enables a pack the user disabled.

use std::io::Read as _;

use crate::rulepack_store::RulePackStore;

pub const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_PACK_ZIP_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PACK_MEMBERS: usize = 256;
pub const MAX_MEMBER_BYTES: u64 = 8 * 1024 * 1024;

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

/// Resolve a pack's `file` against the index URL: absolute URLs win,
/// everything else is relative to the index's directory.
pub fn resolve_pack_url(feed_url: &str, file: &str) -> String {
    if file.contains("://") {
        return file.to_string();
    }
    let base = feed_url.rsplit_once('/').map_or("", |(dir, _)| dir);
    format!("{base}/{file}")
}

pub trait FeedFetcher: Send + Sync {
    fn fetch<'a>(
        &'a mut self,
        url: &'a str,
        max_bytes: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + 'a>>;
}

/// Downloads over the shared HTTP client, enforcing the caller's cap while
/// streaming.
pub struct HttpFeedFetcher {
    pub http: reqwest::Client,
}

impl FeedFetcher for HttpFeedFetcher {
    fn fetch<'a>(
        &'a mut self,
        url: &'a str,
        max_bytes: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + 'a>> {
        Box::pin(async move {
            let response = self
                .http
                .get(url)
                .send()
                .await
                .map_err(|error| format!("request for {url} failed: {error}"))?;
            if !response.status().is_success() {
                return Err(format!("{url} answered {}", response.status()));
            }
            let mut bytes = Vec::new();
            let mut stream = response;
            while let Some(chunk) = stream
                .chunk()
                .await
                .map_err(|error| format!("download from {url} failed: {error}"))?
            {
                if (bytes.len() as u64) + (chunk.len() as u64) > max_bytes {
                    return Err(format!("resource limit: {url} exceeds {max_bytes} bytes"));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FeedUpdateReport {
    pub installed: Vec<String>,
    pub skipped: Vec<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Materialize a pack zip into a private directory: `pack.toml` plus its
/// fixture files, nothing else. Traversal-shaped member names are refused —
/// a feed is as untrusted as anything else downloaded.
fn unpack_pack(zip_bytes: &[u8], directory: &std::path::Path) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
        .map_err(|error| format!("pack archive is not a readable zip: {error}"))?;
    if archive.len() > MAX_PACK_MEMBERS {
        return Err(format!(
            "resource limit: pack archive carries {} members (cap {MAX_PACK_MEMBERS})",
            archive.len()
        ));
    }
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|error| format!("pack archive member {index} is unreadable: {error}"))?;
        // enclosed_name refuses absolute paths and `..` — exactly the two
        // ways a zip path could escape the directory being written.
        let Some(relative) = member.enclosed_name() else {
            return Err(format!(
                "pack archive member {:?} escapes its directory; refusing the archive",
                member.name()
            ));
        };
        if member.is_dir() {
            continue;
        }
        let mut bytes = Vec::new();
        member
            .by_ref()
            .take(MAX_MEMBER_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                format!(
                    "pack archive member {:?} is unreadable: {error}",
                    member.name()
                )
            })?;
        if bytes.len() as u64 >= MAX_MEMBER_BYTES {
            return Err(format!(
                "resource limit: pack archive member {:?} exceeds {MAX_MEMBER_BYTES} bytes",
                member.name()
            ));
        }
        let target = directory.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot unpack pack archive: {error}"))?;
        }
        std::fs::write(&target, &bytes)
            .map_err(|error| format!("cannot unpack pack archive: {error}"))?;
    }
    Ok(())
}

/// Find the pack file: at the archive root, or in the archive's single
/// top-level directory. Returns the fixture root beside it.
fn locate_pack_toml(directory: &std::path::Path) -> Result<(String, std::path::PathBuf), String> {
    let direct = directory.join("pack.toml");
    if direct.is_file() {
        let toml_text = std::fs::read_to_string(&direct)
            .map_err(|error| format!("cannot read pack.toml: {error}"))?;
        return Ok((toml_text, directory.to_path_buf()));
    }
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(directory)
        .map_err(|error| format!("cannot read the unpacked pack: {error}"))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.path().join("pack.toml").is_file() {
            candidates.push(entry.path());
        }
    }
    match candidates.as_slice() {
        [only] => {
            let toml_text = std::fs::read_to_string(only.join("pack.toml"))
                .map_err(|error| format!("cannot read pack.toml: {error}"))?;
            Ok((toml_text, only.clone()))
        }
        [] => Err("pack archive carries no pack.toml".into()),
        _ => Err("pack archive carries more than one pack".into()),
    }
}

/// Update packs from the feed into the store. `only` filters to the listed
/// pack ids; an id the feed does not carry is a usage error, not a skip.
pub async fn update_from_feed<F>(
    store: &RulePackStore,
    feed_url: &str,
    fetcher: &mut dyn FeedFetcher,
    only: &[String],
    mut note: F,
) -> Result<FeedUpdateReport, String>
where
    F: FnMut(String),
{
    let index_bytes = fetcher.fetch(feed_url, MAX_INDEX_BYTES).await?;
    let packs = parse_index(&index_bytes)?;
    if !only.is_empty() {
        let mut missing = Vec::new();
        for id in only {
            if !packs.iter().any(|pack| &pack.id == id) {
                missing.push(id.clone());
            }
        }
        if !missing.is_empty() {
            return Err(format!("the feed does not carry: {}", missing.join(", ")));
        }
    }

    let installed: std::collections::HashMap<String, bool> = store
        .list()
        .into_iter()
        .map(|pack| (pack.id, pack.enabled))
        .collect();

    let mut report = FeedUpdateReport::default();
    for pack in &packs {
        if !only.is_empty() && !only.iter().any(|id| id == &pack.id) {
            continue;
        }
        if let Some(installed) = store.list().iter().find(|row| row.id == pack.id) {
            if installed.version == pack.version {
                note(format!(
                    "{} {} already installed; skipping",
                    pack.id, pack.version
                ));
                report.skipped.push(pack.id.clone());
                continue;
            }
            note(format!(
                "updating {} from {} to {}",
                pack.id, installed.version, pack.version
            ));
        }
        let pack_url = resolve_pack_url(feed_url, &pack.file);
        note(format!("downloading {pack_url}…"));
        let zip_bytes = fetcher.fetch(&pack_url, MAX_PACK_ZIP_BYTES).await?;
        let actual = sha256_hex(&zip_bytes);
        if !actual.eq_ignore_ascii_case(&pack.sha256) {
            return Err(format!(
                "pack {} download failed its digest check: index says sha256:{}, download is sha256:{actual}",
                pack.id, pack.sha256
            ));
        }
        let unpack = tempfile::tempdir().map_err(|error| error.to_string())?;
        unpack_pack(&zip_bytes, unpack.path())?;
        let (toml_text, fixture_root) = locate_pack_toml(unpack.path())?;
        let now = chrono::Utc::now().to_rfc3339();
        store.install(&toml_text, &fixture_root, &now)?;
        // An update never re-enables what the user disabled.
        if installed.get(&pack.id) == Some(&false) {
            store.set_enabled(&pack.id, false)?;
        }
        report.installed.push(pack.id.clone());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureFetcher {
        responses: std::collections::HashMap<String, Result<Vec<u8>, String>>,
    }

    impl FeedFetcher for FixtureFetcher {
        fn fetch<'a>(
            &'a mut self,
            url: &'a str,
            _max_bytes: u64,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + 'a>>
        {
            let outcome = self.responses.get(url).cloned();
            Box::pin(async move { outcome.unwrap_or_else(|| Err(format!("no fixture for {url}"))) })
        }
    }

    fn index_json(packs: &[(&str, &str, &str, &str)]) -> Vec<u8> {
        serde_json::json!({
            "schemaVersion": 1,
            "packs": packs.iter().map(|(id, version, file, sha)| serde_json::json!({
                "id": id, "version": version, "file": file, "sha256": sha
            })).collect::<Vec<_>>()
        })
        .to_string()
        .into_bytes()
    }

    fn pack_zip() -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                "pack.toml".to_string(),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        // The content never reaches validation in the digest test; the
        // store path is exercised by the e2e.
        std::io::Write::write_all(&mut writer, b"# fixture pack").unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn index_parsing_validates_entries() {
        let packs = parse_index(&index_json(&[(
            "org.example",
            "1.0.0",
            "org.example-1.0.0.zip",
            &"a".repeat(64),
        )]))
        .unwrap();
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].id, "org.example");

        for broken in [
            b"{}".as_slice(),
            br#"{"schemaVersion":2,"packs":[]}"#.as_slice(),
            br#"{"schemaVersion":1}"#.as_slice(),
            br#"{"schemaVersion":1,"packs":[{"id":"x"}]}"#.as_slice(),
            // malformed digest
            br#"{"schemaVersion":1,"packs":[{"id":"x","version":"1","file":"x.zip","sha256":"zz"}]}"#.as_slice(),
        ] {
            assert!(parse_index(broken).is_err(), "{}", String::from_utf8_lossy(broken));
        }
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let entry = (
            "org.example",
            "1.0.0",
            "a.zip",
            &(0..64)
                .map(|i| if i % 2 == 0 { 'a' } else { 'b' })
                .collect::<String>(),
        );
        let (id, version, file, sha) = entry;
        let json = serde_json::json!({
            "schemaVersion": 1,
            "packs": [
                {"id": id, "version": version, "file": file, "sha256": sha},
                {"id": id, "version": "2.0.0", "file": "b.zip", "sha256": sha}
            ]
        })
        .to_string();
        assert!(parse_index(json.as_bytes()).is_err());
    }

    #[test]
    fn pack_urls_resolve_against_the_index_directory() {
        assert_eq!(
            resolve_pack_url("https://example.com/feed/index.json", "pack-1.zip"),
            "https://example.com/feed/pack-1.zip"
        );
        assert_eq!(
            resolve_pack_url(
                "https://example.com/feed/index.json",
                "https://mirror.example/pack-1.zip"
            ),
            "https://mirror.example/pack-1.zip"
        );
    }

    #[tokio::test]
    async fn a_failed_digest_check_never_reaches_the_store() {
        let store = RulePackStore::open_in_memory().unwrap();
        let zip = pack_zip();
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "https://example.com/feed/index.json".to_string(),
            Ok(index_json(&[(
                "org.example",
                "1.0.0",
                "pack.zip",
                &(0..64)
                    .map(|i| if i % 2 == 0 { 'a' } else { 'f' })
                    .collect::<String>(),
            )])),
        );
        responses.insert("https://example.com/feed/pack.zip".to_string(), Ok(zip));
        let mut fetcher = FixtureFetcher { responses };
        let error = update_from_feed(
            &store,
            "https://example.com/feed/index.json",
            &mut fetcher,
            &[],
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(error.contains("digest"), "{error}");
        assert!(store.list().is_empty());
    }

    #[tokio::test]
    async fn unknown_only_ids_are_usage_errors() {
        let store = RulePackStore::open_in_memory().unwrap();
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "https://example.com/feed/index.json".to_string(),
            Ok(index_json(&[(
                "org.example",
                "1.0.0",
                "pack.zip",
                &"a".repeat(64),
            )])),
        );
        let mut fetcher = FixtureFetcher { responses };
        let error = update_from_feed(
            &store,
            "https://example.com/feed/index.json",
            &mut fetcher,
            &["org.absent".to_string()],
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(error.contains("org.absent"), "{error}");
    }

    #[test]
    fn traversal_members_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                "../escape.txt".to_string(),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        std::io::Write::write_all(&mut writer, b"no").unwrap();
        let zip = writer.finish().unwrap().into_inner();
        let error = unpack_pack(&zip, directory.path()).unwrap_err();
        assert!(error.contains("escapes"), "{error}");
    }
}
