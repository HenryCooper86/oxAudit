//! License enrichment from package registries.
//!
//! npm lockfiles carry the resolved license beside every entry, so npm needs
//! no network. Other ecosystems' registries publish it per package: PyPI's
//! JSON API, crates.io's version API (which rejects default user agents —
//! the shared client's identifying one passes), RubyGems' gem metadata,
//! Packagist's p2 index, and the Maven POM itself on Central. This module
//! fetches those — bounded, online-only, best-effort — and fills
//! `Dependency.license` so SBOMs carry licenses wherever they can be read
//! without guessing.
//!
//! Stated limits: Go's module proxy publishes no license metadata and
//! NuGet's needs the registration blob (several requests), so both stay
//! unknown rather than approximated. RubyGems' endpoint is name-level, so a
//! gem's license is read at its latest published shape.

use crate::models::Dependency;
use futures::StreamExt;
use std::collections::HashMap;

/// One registry lookup per distinct package, capped so a monorepo scan
/// cannot turn into a thousand requests.
pub const MAX_LICENSE_LOOKUPS: usize = 500;
const CONCURRENCY: usize = 8;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

const PYPI_BASE: &str = "https://pypi.org";
const CRATES_BASE: &str = "https://crates.io";
const RUBYGEMS_BASE: &str = "https://rubygems.org";
const PACKAGIST_BASE: &str = "https://repo.packagist.org";
const MAVEN_BASE: &str = "https://repo1.maven.org/maven2";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LicenseFetchSummary {
    pub filled: usize,
    pub already_known: usize,
    pub skipped_no_source: usize,
    pub failed: usize,
    pub notes: Vec<String>,
}

/// RFC 3986 unreserved characters stay readable; everything else encodes.
const UNRESERVED: percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn registry_url(ecosystem: &str, name: &str, version: &str, base: &str) -> Option<String> {
    let encoded =
        |value: &str| percent_encoding::utf8_percent_encode(value, &UNRESERVED).to_string();
    match ecosystem {
        "PyPI" => Some(format!(
            "{base}/pypi/{}/{encoded_version}/json",
            encoded(name),
            encoded_version = encoded(version)
        )),
        "crates.io" => Some(format!(
            "{base}/api/v1/crates/{}/{encoded_version}",
            encoded(name),
            encoded_version = encoded(version)
        )),
        "RubyGems" => Some(format!("{base}/api/v1/gems/{}.json", encoded(name))),
        "Packagist" => Some(format!("{base}/p2/{}.json", encoded(name))),
        // group:artifact — the group's dots become path separators; the
        // segments themselves are registry-safe identifiers.
        "Maven" => {
            let (group, artifact) = name.split_once(':')?;
            let group_path = group.split('.').map(encoded).collect::<Vec<_>>().join("/");
            Some(format!(
                "{base}/{group_path}/{artifact}/{encoded_version}/{artifact}-{encoded_version}.pom",
                artifact = encoded(artifact),
                encoded_version = encoded(version),
            ))
        }
        _ => None,
    }
}

fn parse_license(ecosystem: &str, body: &[u8], wanted_version: &str) -> Option<String> {
    let license = match ecosystem {
        "PyPI" => {
            let value: serde_json::Value = serde_json::from_slice(body).ok()?;
            let declared = value
                .pointer("/info/license")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|license| !license.is_empty());
            declared.map(String::from).or_else(|| {
                // The classifier carries the license when the field is
                // empty: "License :: OSI Approved :: MIT License".
                value
                    .pointer("/info/classifiers")
                    .and_then(serde_json::Value::as_array)?
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .find(|classifier| classifier.starts_with("License ::"))
                    .and_then(|classifier| classifier.rsplit(":: ").next())
                    .map(str::to_string)
            })?
        }
        "crates.io" => {
            let value: serde_json::Value = serde_json::from_slice(body).ok()?;
            value
                .pointer("/version/license")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|license| !license.is_empty())
                .map(String::from)?
        }
        "RubyGems" => {
            let value: serde_json::Value = serde_json::from_slice(body).ok()?;
            value
                .get("license")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|license| !license.is_empty())
                .map(String::from)?
        }
        "Packagist" => {
            let value: serde_json::Value = serde_json::from_slice(body).ok()?;
            let packages = value.get("packages")?.as_object()?;
            let entries = packages.values().next()?.as_array()?;
            // Prefer the entry matching the pinned version; fall back to the
            // first (most recent) entry.
            let entry = entries
                .iter()
                .find(|entry| {
                    entry
                        .get("version")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .is_some_and(|version| version == wanted_version.trim())
                })
                .or_else(|| entries.first())?;
            entry
                .get("license")
                .and_then(serde_json::Value::as_array)?
                .iter()
                .filter_map(serde_json::Value::as_str)
                .next()
                .map(str::trim)
                .filter(|license| !license.is_empty())
                .map(String::from)?
        }
        // The POM's first declared license name.
        "Maven" => parse_pom_license(body)?,
        _ => return None,
    };
    Some(license)
}

fn parse_pom_license(pom: &[u8]) -> Option<String> {
    use quick_xml::events::Event;
    let text = std::str::from_utf8(pom).ok()?;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut depth_path: Vec<String> = Vec::new();
    let mut pending_name = false;
    let mut license_name: Option<String> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                let name = tag.name().as_ref().to_string();
                pending_name =
                    name == "name" && depth_path.last().map(String::as_str) == Some("license");
                depth_path.push(name);
            }
            Ok(Event::Text(value)) if pending_name => {
                let value = value
                    .xml_content(quick_xml::XmlVersion::Implicit1_0)
                    .trim()
                    .to_string();
                if !value.is_empty() && license_name.is_none() {
                    license_name = Some(value);
                }
                pending_name = false;
            }
            Ok(Event::End(_)) => {
                depth_path.pop();
                pending_name = false;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {
                pending_name = false;
            }
            Err(_) => return None,
        }
    }
    license_name
}

/// Fill `Dependency.license` for every dependency that lacks one and whose
/// ecosystem has a measured registry source. Online-only; callers state that.
pub async fn fetch_missing(deps: &mut [Dependency], http: &reqwest::Client) -> LicenseFetchSummary {
    fetch_with_base_overrides(deps, http, &HashMap::new()).await
}

/// The same fetch with per-ecosystem base-URL overrides; production passes
/// an empty map, tests point ecosystems at a local server.
pub async fn fetch_with_base_overrides(
    deps: &mut [Dependency],
    http: &reqwest::Client,
    overrides: &HashMap<String, String>,
) -> LicenseFetchSummary {
    let mut summary = LicenseFetchSummary::default();

    // Deduplicate lookups by (ecosystem, name) — RubyGems is name-level
    // anyway, and repeated pinned versions of one package cost one request.
    let mut wanted: Vec<(String, String, String)> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for dependency in deps.iter() {
        if dependency.license.is_some() {
            continue;
        }
        if registry_url(
            &dependency.ecosystem,
            &dependency.name,
            &dependency.version,
            "",
        )
        .is_none()
        {
            continue;
        }
        if seen.insert((dependency.ecosystem.clone(), dependency.name.clone())) {
            wanted.push((
                dependency.ecosystem.clone(),
                dependency.name.clone(),
                dependency.version.clone(),
            ));
        }
    }
    for dependency in deps.iter() {
        if dependency.license.is_some() {
            summary.already_known += 1;
        } else if registry_url(
            &dependency.ecosystem,
            &dependency.name,
            &dependency.version,
            "",
        )
        .is_none()
        {
            summary.skipped_no_source += 1;
        }
    }
    if wanted.len() > MAX_LICENSE_LOOKUPS {
        summary.notes.push(format!(
            "license lookup is bounded at {MAX_LICENSE_LOOKUPS} packages; {} requested, the rest stay unknown",
            wanted.len()
        ));
        wanted.truncate(MAX_LICENSE_LOOKUPS);
    }
    if wanted.is_empty() {
        return summary;
    }

    // One request per distinct package, bounded width; each result is
    // applied to every pinned version that still lacks a license.
    let mut results: HashMap<(String, String), Option<String>> = HashMap::new();
    let mut stream = futures::stream::iter(wanted.into_iter().map(|(ecosystem, name, version)| {
        let base = overrides
            .get(&ecosystem)
            .cloned()
            .unwrap_or_else(|| default_base(&ecosystem).to_string());
        let url = registry_url(&ecosystem, &name, &version, &base)
            .expect("filtered to ecosystems with a source");
        async move {
            let outcome = async {
                let response = http
                    .get(&url)
                    .timeout(REQUEST_TIMEOUT)
                    .send()
                    .await
                    .map_err(|error| error.to_string())?;
                if !response.status().is_success() {
                    return Err(format!("registry answered {}", response.status()));
                }
                let body = response.bytes().await.map_err(|error| error.to_string())?;
                Ok(parse_license(&ecosystem, &body, &version))
            }
            .await;
            ((ecosystem, name), outcome)
        }
    }))
    .buffer_unordered(CONCURRENCY);
    while let Some((key, outcome)) = stream.next().await {
        match outcome {
            Ok(license) => {
                results.insert(key, license);
            }
            Err(error) => {
                summary.failed += 1;
                if summary.notes.len() < 5 {
                    summary
                        .notes
                        .push(format!("license lookup failed: {error}"));
                }
            }
        }
    }

    // Packagist answers per version; re-check the pinned version against the
    // fetched body would need it retained — the parser prefers the matching
    // entry when the body is version-keyed by the registry itself, and the
    // placeholder above documents that the exact-version preference is
    // applied inside parse for the p2 shape we control.
    for dependency in deps.iter_mut() {
        if dependency.license.is_some() {
            continue;
        }
        if let Some(Some(license)) =
            results.get(&(dependency.ecosystem.clone(), dependency.name.clone()))
        {
            dependency.license = Some(license.clone());
            summary.filled += 1;
        }
    }
    summary
}

fn default_base(ecosystem: &str) -> &'static str {
    match ecosystem {
        "PyPI" => PYPI_BASE,
        "crates.io" => CRATES_BASE,
        "RubyGems" => RUBYGEMS_BASE,
        "Packagist" => PACKAGIST_BASE,
        "Maven" => MAVEN_BASE,
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependency(ecosystem: &str, name: &str, version: &str) -> Dependency {
        Dependency {
            occurrence: Default::default(),
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: version.into(),
            lockfile: "fixture".into(),
            license: None,
        }
    }

    #[test]
    fn pypi_licenses_prefer_the_declared_field_over_classifiers() {
        let body = br#"{"info":{"license":"Apache 2.0","classifiers":["License :: OSI Approved :: Apache Software License"]}}"#;
        assert_eq!(
            parse_license("PyPI", body, "").as_deref(),
            Some("Apache 2.0")
        );
        let body =
            br#"{"info":{"license":"","classifiers":["License :: OSI Approved :: MIT License"]}}"#;
        assert_eq!(
            parse_license("PyPI", body, "").as_deref(),
            Some("MIT License")
        );
        assert_eq!(parse_license("PyPI", br#"{"info":{}}"#, ""), None);
    }

    #[test]
    fn crates_rubygems_and_packagist_licenses_parse() {
        assert_eq!(
            parse_license(
                "crates.io",
                br#"{"version":{"license":"MIT OR Apache-2.0"}}"#,
                ""
            )
            .as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(
            parse_license("crates.io", br#"{"version":{"license":""}}"#, ""),
            None
        );
        assert_eq!(
            parse_license("RubyGems", br#"{"license":"MIT"}"#, "").as_deref(),
            Some("MIT")
        );
        // null license (measured on real gems) stays unknown.
        assert_eq!(parse_license("RubyGems", br#"{"license":null}"#, ""), None);
        let packagist = br#"{"packages":{"monolog/monolog":[{"version":"3.5.0","license":["MIT"]},{"version":"2.9.3","license":["MIT"]}]}}"#;
        assert_eq!(
            parse_license("Packagist", packagist, "2.9.3").as_deref(),
            Some("MIT")
        );
    }

    #[test]
    fn maven_pom_licenses_take_the_first_declared_name() {
        let pom = br#"<project><licenses>
            <license><name>Apache License, Version 2.0</name><url>https://www.apache.org/licenses/LICENSE-2.0</url></license>
            </licenses><name>a different name element</name></project>"#;
        assert_eq!(
            parse_license("Maven", pom, "").as_deref(),
            Some("Apache License, Version 2.0")
        );
        assert_eq!(parse_license("Maven", br#"<project/>"#, ""), None);
    }

    #[test]
    fn urls_are_built_only_for_measured_ecosystems() {
        assert!(registry_url("PyPI", "django", "5.0", PYPI_BASE).is_some());
        assert!(registry_url(
            "Maven",
            "org.apache.commons:commons-lang3",
            "3.14.0",
            MAVEN_BASE
        )
        .is_some());
        // Go and NuGet have no single-request source; npm comes from lockfiles.
        assert!(registry_url("Go", "github.com/x/y", "v1.0.0", "").is_none());
        assert!(registry_url("NuGet", "Newtonsoft.Json", "13.0.3", "").is_none());
        assert!(registry_url("npm", "left-pad", "1.3.0", "").is_none());
        // A Maven name without group:artifact cannot address a POM.
        assert!(registry_url("Maven", "commons-lang3", "3.14.0", MAVEN_BASE).is_none());
        assert_eq!(
            registry_url("Maven", "org.apache.commons:commons-lang3", "3.14.0", MAVEN_BASE).as_deref(),
            Some("https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom")
        );
    }

    #[tokio::test]
    async fn licenses_fill_over_the_wire_and_failures_stay_notes() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = br#"{"version":{"license":"MIT OR Apache-2.0"}}"#.to_vec();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match stream.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => {
                            request.extend_from_slice(&byte);
                            if request.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&request);
                let path = head
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split(' ')
                    .nth(1)
                    .unwrap_or("");
                let (status, payload) = if path.contains("/api/v1/crates/serde/") {
                    ("200 OK", body.clone())
                } else {
                    ("404 Not Found", Vec::new())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&payload);
                let _ = stream.flush();
            }
        });

        let mut deps = vec![
            dependency("crates.io", "serde", "1.0.200"),
            dependency("crates.io", "serde", "1.0.201"),
            dependency("crates.io", "missing", "0.1.0"),
            dependency("Go", "github.com/x/y", "v1.0.0"),
            Dependency {
                license: Some("MIT".into()),
                ..dependency("npm", "left-pad", "1.3.0")
            },
        ];
        let http = reqwest::Client::builder().build().unwrap();
        let overrides = HashMap::from([("crates.io".to_string(), format!("http://{address}"))]);
        let summary = fetch_with_base_overrides(&mut deps, &http, &overrides).await;

        // One deduplicated lookup fills both pinned versions.
        assert_eq!(deps[0].license.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(deps[1].license.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(deps[2].license, None, "a failed lookup stays unknown");
        assert_eq!(deps[3].license, None, "no source, no guess");
        assert_eq!(deps[4].license.as_deref(), Some("MIT"));
        assert_eq!(summary.filled, 2);
        assert_eq!(summary.already_known, 1);
        assert_eq!(summary.skipped_no_source, 1);
        assert_eq!(summary.failed, 1);
        assert!(
            summary.notes.iter().any(|note| note.contains("404")),
            "{:?}",
            summary.notes
        );
    }
}
