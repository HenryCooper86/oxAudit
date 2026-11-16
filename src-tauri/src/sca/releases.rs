//! Release facts from the deps.dev package index.
//!
//! One request per distinct package answers, for every published version,
//! when it was published, whether the registry serves it by default and
//! whether it is deprecated. From that this module derives the facts the
//! component policy's operational rules read: the installed version's age,
//! how far it trails the default release, and when the package last
//! published anything.
//!
//! Online-only, bounded and best-effort, like license enrichment. A package
//! the index does not cover, a lookup that fails and a version the index
//! does not list all leave the fact unknown. Nothing is estimated.

use std::collections::{BTreeMap, BTreeSet};

use futures::StreamExt;
use oxaudit_sca::ReleaseInfo;

use crate::advisories::versioning;
use crate::models::Dependency;

/// One request per distinct package, capped like license lookups.
pub const MAX_RELEASE_LOOKUPS: usize = 500;
const CONCURRENCY: usize = 8;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// A package with thousands of versions still answers well under this.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_BASE: &str = "https://api.deps.dev";

const UNRESERVED: percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// What a fetch produced. `releases` holds one entry per installed version
/// the index stated at least one fact about.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReleaseFetch {
    pub releases: Vec<ReleaseInfo>,
    /// Distinct packages asked about.
    pub requested: usize,
    pub failed: usize,
    /// Packages in ecosystems the index does not cover.
    pub skipped_no_source: usize,
    pub notes: Vec<String>,
}

/// The index's name for an ecosystem, or `None` when it has no coverage.
fn system(ecosystem: &str) -> Option<&'static str> {
    Some(match ecosystem {
        "npm" => "NPM",
        "PyPI" => "PYPI",
        "Maven" => "MAVEN",
        "crates.io" => "CARGO",
        "Go" => "GO",
        "NuGet" => "NUGET",
        "RubyGems" => "RUBYGEMS",
        _ => return None,
    })
}

/// The package name in the form the index keys it by.
fn index_name(ecosystem: &str, name: &str) -> String {
    match ecosystem {
        "PyPI" => versioning::normalize_package("PyPI", name),
        "NuGet" => name.to_lowercase(),
        _ => name.to_string(),
    }
}

fn package_url(base: &str, ecosystem: &str, name: &str) -> Option<String> {
    let system = system(ecosystem)?;
    let name = index_name(ecosystem, name);
    Some(format!(
        "{base}/v3/systems/{system}/packages/{}",
        percent_encoding::utf8_percent_encode(&name, &UNRESERVED)
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedVersion {
    version: String,
    published_at: Option<String>,
    is_default: bool,
    deprecated: Option<bool>,
    deprecated_reason: Option<String>,
}

fn parse_package(body: &[u8]) -> Result<Vec<IndexedVersion>, String> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| format!("unreadable index answer: {error}"))?;
    let versions = value
        .get("versions")
        .and_then(serde_json::Value::as_array)
        .ok_or("index answer has no versions list")?;
    Ok(versions
        .iter()
        .filter_map(|entry| {
            let version = entry.pointer("/versionKey/version")?.as_str()?.to_string();
            let published_at = entry
                .get("publishedAt")
                .and_then(serde_json::Value::as_str)
                .filter(|stamp| chrono::DateTime::parse_from_rfc3339(stamp).is_ok())
                .map(String::from);
            Some(IndexedVersion {
                version,
                published_at,
                is_default: entry.get("isDefault").and_then(serde_json::Value::as_bool)
                    == Some(true),
                deprecated: entry
                    .get("isDeprecated")
                    .and_then(serde_json::Value::as_bool),
                deprecated_reason: entry
                    .get("deprecatedReason")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|reason| !reason.is_empty())
                    .map(|reason| reason.chars().take(300).collect()),
            })
        })
        .collect())
}

/// Go module versions carry a leading `v` in the index and may not in an
/// inventory; everywhere else the strings must match exactly.
fn same_version(ecosystem: &str, indexed: &str, installed: &str) -> bool {
    indexed == installed
        || (ecosystem == "Go"
            && indexed.trim_start_matches('v') == installed.trim_start_matches('v'))
}

/// The leading numeric component, for counting major versions.
fn major(version: &str) -> Option<u32> {
    let digits: String = version
        .trim_start_matches('v')
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let rest = &version.trim_start_matches('v')[digits.len()..];
    // `1!2.0` (a PEP 440 epoch) or `2024a` does not start with a major version.
    if digits.is_empty() || !(rest.is_empty() || rest.starts_with(['.', '-', '+'])) {
        return None;
    }
    digits.parse().ok()
}

/// Derive the facts for one installed version from the package's index entry.
fn facts(ecosystem: &str, name: &str, installed: &str, indexed: &[IndexedVersion]) -> ReleaseInfo {
    let mut info = ReleaseInfo {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version: installed.to_string(),
        ..Default::default()
    };
    if let Some(own) = indexed
        .iter()
        .find(|entry| same_version(ecosystem, &entry.version, installed))
    {
        info.published_at = own.published_at.clone();
        info.deprecated = own.deprecated;
        info.deprecated_reason = own.deprecated_reason.clone();
    }
    let default = indexed.iter().find(|entry| entry.is_default);
    info.latest_version = default.map(|entry| entry.version.clone());
    info.latest_published_at = indexed
        .iter()
        .filter_map(|entry| {
            let stamp = entry.published_at.as_deref()?;
            let parsed = chrono::DateTime::parse_from_rfc3339(stamp).ok()?;
            Some((parsed, stamp))
        })
        .max_by_key(|(parsed, _)| *parsed)
        .map(|(_, stamp)| stamp.to_string());
    if let Some(family) = versioning::family_for("ECOSYSTEM", ecosystem) {
        // Count only when the installed version itself can be ordered.
        if versioning::compare(family, installed, installed).is_some() {
            let newer = indexed
                .iter()
                .filter(|entry| {
                    versioning::compare(family, &entry.version, installed)
                        == Some(std::cmp::Ordering::Greater)
                })
                .count();
            info.newer_versions = u32::try_from(newer).ok();
        }
    }
    if let (Some(latest), Some(current)) = (
        default.and_then(|entry| major(&entry.version)),
        major(installed),
    ) {
        info.major_versions_behind = Some(latest.saturating_sub(current));
    }
    info
}

async fn fetch_body(http: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let mut response = http
        .get(url)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await
        .map_err(|error| error.without_url().to_string())?;
    if !response.status().is_success() {
        return Err(format!("the index answered {}", response.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| error.without_url().to_string())?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err("the index answer exceeds the size limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Fetch release facts for every registry dependency. `base` is the index's
/// origin; production passes [`DEFAULT_BASE`].
pub async fn fetch(deps: &[Dependency], http: &reqwest::Client, base: &str) -> ReleaseFetch {
    let mut outcome = ReleaseFetch::default();
    let mut wanted: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut uncovered = BTreeSet::new();
    for dependency in deps
        .iter()
        .filter(|dependency| crate::deps::osv::is_queryable_dependency(dependency))
    {
        let key = (dependency.ecosystem.clone(), dependency.name.clone());
        if system(&dependency.ecosystem).is_none() {
            uncovered.insert(key);
            continue;
        }
        wanted
            .entry(key)
            .or_default()
            .insert(dependency.version.clone());
    }
    outcome.skipped_no_source = uncovered.len();
    if outcome.skipped_no_source > 0 {
        outcome.notes.push(format!(
            "release facts are not available for {} package(s) in ecosystems the index does not cover",
            outcome.skipped_no_source
        ));
    }
    if wanted.len() > MAX_RELEASE_LOOKUPS {
        outcome.notes.push(format!(
            "release lookup is bounded at {MAX_RELEASE_LOOKUPS} packages; {} requested, the rest stay unknown",
            wanted.len()
        ));
        wanted = wanted.into_iter().take(MAX_RELEASE_LOOKUPS).collect();
    }
    outcome.requested = wanted.len();

    let mut stream =
        futures::stream::iter(wanted.into_iter().map(|((ecosystem, name), versions)| {
            let url = package_url(base, &ecosystem, &name).expect("filtered to covered ecosystems");
            async move {
                let answer = match fetch_body(http, &url).await {
                    Ok(body) => parse_package(&body),
                    Err(error) => Err(error),
                };
                (ecosystem, name, versions, answer)
            }
        }))
        .buffer_unordered(CONCURRENCY);
    while let Some((ecosystem, name, versions, answer)) = stream.next().await {
        match answer {
            Ok(indexed) => {
                for version in versions {
                    let info = facts(&ecosystem, &name, &version, &indexed);
                    if info.has_facts() {
                        outcome.releases.push(info);
                    }
                }
            }
            Err(error) => {
                outcome.failed += 1;
                if outcome.notes.len() < 5 {
                    outcome.notes.push(format!(
                        "release lookup failed for {ecosystem} {name}: {error}"
                    ));
                }
            }
        }
    }
    outcome.releases.sort_by(|left, right| {
        (&left.ecosystem, &left.name, &left.version).cmp(&(
            &right.ecosystem,
            &right.name,
            &right.version,
        ))
    });
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dependency(ecosystem: &str, name: &str, version: &str) -> Dependency {
        Dependency {
            occurrence: Default::default(),
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: version.into(),
            lockfile: "lock".into(),
            license: None,
        }
    }

    fn index(entries: &[(&str, &str, bool, Option<bool>)]) -> Vec<u8> {
        let versions: Vec<_> = entries
            .iter()
            .map(|(version, published, default, deprecated)| {
                let mut entry = json!({
                    "versionKey": {"system": "NPM", "name": "x", "version": version},
                    "publishedAt": published,
                    "isDefault": default,
                });
                if let Some(deprecated) = deprecated {
                    entry["isDeprecated"] = json!(deprecated);
                    entry["deprecatedReason"] = json!("  use y instead ");
                }
                entry
            })
            .collect();
        json!({"packageKey": {"system": "NPM", "name": "x"}, "versions": versions})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn urls_use_the_index_name_and_encode_it() {
        assert_eq!(
            package_url("https://i", "npm", "@scope/pkg").as_deref(),
            Some("https://i/v3/systems/NPM/packages/%40scope%2Fpkg")
        );
        assert_eq!(
            package_url("https://i", "PyPI", "Django_Rest").as_deref(),
            Some("https://i/v3/systems/PYPI/packages/django-rest")
        );
        assert_eq!(
            package_url("https://i", "Maven", "org.x:y").as_deref(),
            Some("https://i/v3/systems/MAVEN/packages/org.x%3Ay")
        );
        assert_eq!(
            package_url("https://i", "NuGet", "Newtonsoft.Json").as_deref(),
            Some("https://i/v3/systems/NUGET/packages/newtonsoft.json")
        );
        assert_eq!(package_url("https://i", "Hex", "plug"), None);
    }

    #[test]
    fn facts_come_only_from_what_the_index_states() {
        let indexed = parse_package(&index(&[
            ("1.0.0", "2020-01-01T00:00:00Z", false, Some(true)),
            ("1.5.0", "2021-01-01T00:00:00Z", false, None),
            ("3.1.0", "2025-06-01T00:00:00Z", true, Some(false)),
            ("4.0.0-beta.1", "2026-02-01T00:00:00Z", false, None),
            ("garbage", "not a date", false, None),
        ]))
        .unwrap();
        let old = facts("npm", "x", "1.0.0", &indexed);
        assert_eq!(old.published_at.as_deref(), Some("2020-01-01T00:00:00Z"));
        assert_eq!(old.deprecated, Some(true));
        assert_eq!(old.deprecated_reason.as_deref(), Some("use y instead"));
        assert_eq!(old.latest_version.as_deref(), Some("3.1.0"));
        // The newest publication of any version, pre-release included.
        assert_eq!(
            old.latest_published_at.as_deref(),
            Some("2026-02-01T00:00:00Z")
        );
        assert_eq!(old.newer_versions, Some(3));
        assert_eq!(old.major_versions_behind, Some(2));

        // A version the index does not list: its own facts stay unknown.
        let unlisted = facts("npm", "x", "2.0.0", &indexed);
        assert_eq!(unlisted.published_at, None);
        assert_eq!(unlisted.deprecated, None);
        assert_eq!(unlisted.major_versions_behind, Some(1));
        assert!(unlisted.has_facts());

        // Ahead of the default release is zero behind, never negative.
        assert_eq!(
            facts("npm", "x", "9.0.0", &indexed).major_versions_behind,
            Some(0)
        );
        // No default version stated: nothing to be behind.
        let none =
            parse_package(&index(&[("1.0.0", "2020-01-01T00:00:00Z", false, None)])).unwrap();
        assert_eq!(
            facts("npm", "x", "1.0.0", &none).major_versions_behind,
            None
        );
        assert_eq!(facts("npm", "x", "1.0.0", &none).latest_version, None);
    }

    #[test]
    fn major_versions_parse_only_when_the_version_starts_with_one() {
        assert_eq!(major("v2.3.4"), Some(2));
        assert_eq!(major("10"), Some(10));
        assert_eq!(major("3-beta"), Some(3));
        assert_eq!(major("1!2.0"), None);
        assert_eq!(major("2024a"), None);
        assert_eq!(major("beta"), None);
        assert!(same_version("Go", "v1.2.3", "1.2.3"));
        assert!(!same_version("npm", "v1.2.3", "1.2.3"));
    }

    #[test]
    fn malformed_answers_are_errors_not_empty_facts() {
        assert!(parse_package(b"<html>").is_err());
        assert!(parse_package(br#"{"packageKey": {}}"#).is_err());
        assert_eq!(
            parse_package(br#"{"versions": [{"nope": 1}]}"#).unwrap(),
            vec![]
        );
    }

    async fn serve(
        responses: Vec<(u16, Vec<u8>)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut paths = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8_lossy(&header).to_string();
                paths.push(request.split_whitespace().nth(1).unwrap_or("").to_string());
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.ok();
            }
            paths
        });
        (url, server)
    }

    #[tokio::test]
    async fn fetch_asks_once_per_package_and_skips_what_it_cannot_ask_about() {
        let (url, server) = serve(vec![(
            200,
            index(&[
                ("1.0.0", "2020-01-01T00:00:00Z", false, None),
                ("2.0.0", "2024-01-01T00:00:00Z", true, None),
            ]),
        )])
        .await;
        let mut local = dependency("npm", "workspace-app", "0.0.0");
        local.occurrence.local_workspace = true;
        let deps = vec![
            dependency("npm", "x", "1.0.0"),
            dependency("npm", "x", "2.0.0"),
            dependency("npm", "x", "1.0.0"),
            dependency("Hex", "plug", "1.0.0"),
            local,
        ];
        let outcome = fetch(&deps, &reqwest::Client::new(), &url).await;
        assert_eq!(outcome.requested, 1);
        assert_eq!(outcome.failed, 0);
        assert_eq!(outcome.skipped_no_source, 1);
        assert_eq!(outcome.releases.len(), 2);
        assert_eq!(outcome.releases[0].major_versions_behind, Some(1));
        assert_eq!(outcome.releases[1].major_versions_behind, Some(0));
        assert!(
            outcome.notes[0].contains("does not cover"),
            "{:?}",
            outcome.notes
        );
        assert_eq!(server.await.unwrap(), vec!["/v3/systems/NPM/packages/x"]);
    }

    #[tokio::test]
    async fn a_failed_lookup_is_counted_and_leaves_the_facts_unknown() {
        let (url, server) = serve(vec![(404, b"{}".to_vec())]).await;
        let outcome = fetch(
            &[dependency("npm", "ghost", "1.0.0")],
            &reqwest::Client::new(),
            &url,
        )
        .await;
        assert_eq!(outcome.requested, 1);
        assert_eq!(outcome.failed, 1);
        assert!(outcome.releases.is_empty());
        assert!(
            outcome.notes[0].contains("npm ghost"),
            "{:?}",
            outcome.notes
        );
        assert!(
            !outcome.notes[0].contains("127.0.0.1"),
            "{:?}",
            outcome.notes
        );
        server.await.unwrap();
    }
}
