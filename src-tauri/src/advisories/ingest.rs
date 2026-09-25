//! Build a local advisory database from OSV's published ecosystem dumps.
//!
//! OSV publishes one zip per ecosystem at
//! `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`,
//! each member a full advisory record. Ingestion streams a member at a time
//! under explicit budgets, refuses malformed records by name rather than
//! skipping them (a half-populated database must not be presented as
//! coverage), and advances the coverage list only after every requested
//! ecosystem ingested completely — a failed update leaves already-downloaded
//! rows inert but never widens what queries are allowed to answer.

use std::io::Read;

use serde_json::Value;

use super::store::AdvisoryDb;

pub const OSV_DUMP_BASE: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// The ecosystems oxAudit's lockfile parsers can produce queries for; the
/// default set `advisory-db update` downloads.
pub const DEFAULT_ECOSYSTEMS: [&str; 8] = [
    "npm",
    "PyPI",
    "Maven",
    "crates.io",
    "Go",
    "RubyGems",
    "Packagist",
    "NuGet",
];

/// One ecosystem dump is expected in the hundreds of megabytes; two gigabytes
/// is a ceiling that stops a redirect loop or a hostile mirror, not a size
/// any real dump approaches.
const MAX_ZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS_PER_ECOSYSTEM: usize = 300_000;

pub trait DumpFetcher: Send + Sync {
    fn fetch<'a>(
        &'a mut self,
        ecosystem: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + 'a>>;
}

/// Downloads `<base>/<ecosystem>/all.zip` over the shared HTTP client.
pub struct HttpDumpFetcher {
    http: reqwest::Client,
    base: String,
}

impl HttpDumpFetcher {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            base: OSV_DUMP_BASE.to_string(),
        }
    }

    /// Point at a different dump base (a mirror, or a local test server).
    pub fn with_base(http: reqwest::Client, base: &str) -> Self {
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn url_for(&self, ecosystem: &str) -> String {
        let encoded =
            percent_encoding::utf8_percent_encode(ecosystem, percent_encoding::NON_ALPHANUMERIC);
        format!("{}/{}", self.base, encoded)
    }
}

impl DumpFetcher for HttpDumpFetcher {
    fn fetch<'a>(
        &'a mut self,
        ecosystem: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + 'a>> {
        let url = self.url_for(ecosystem);
        Box::pin(async move {
            let response = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|error| format!("{ecosystem} dump request failed: {error}"))?;
            if !response.status().is_success() {
                return Err(format!(
                    "{ecosystem} dump request returned {} for {url}",
                    response.status()
                ));
            }
            let mut bytes = Vec::new();
            let mut stream = response;
            while let Some(chunk) = stream
                .chunk()
                .await
                .map_err(|error| format!("{ecosystem} dump download failed: {error}"))?
            {
                if (bytes.len() as u64) + (chunk.len() as u64) > MAX_ZIP_BYTES {
                    return Err(format!(
                        "resource limit: the {ecosystem} dump exceeds {} bytes",
                        MAX_ZIP_BYTES
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
    }
}

#[derive(Debug)]
pub struct EcosystemReport {
    pub ecosystem: String,
    pub records: usize,
    pub zip_bytes: u64,
}

#[derive(Debug)]
pub struct UpdateReport {
    pub ecosystems: Vec<EcosystemReport>,
    pub total_advisories: usize,
    pub total_packages: usize,
    pub built_at_ms: u64,
}

fn valid_member_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && name.ends_with(".json")
}

/// One validated dump member: its advisory id, modified stamp, the full
/// record, and the (ecosystem, normalized package) pairs it affects.
struct ParsedMember {
    id: String,
    modified: Option<String>,
    record: Value,
    packages: Vec<(String, String)>,
}

/// Validate one dump member. Returns Err naming the member when anything
/// about it is not what an OSV dump contains — skipping it silently would
/// overstate coverage.
fn parse_member(member_name: &str, bytes: &[u8]) -> Result<ParsedMember, String> {
    if !valid_member_name(member_name) {
        return Err(format!(
            "dump member {member_name:?} is not an advisory record name; refusing the archive"
        ));
    }
    let id = member_name.trim_end_matches(".json").to_string();
    if id.is_empty() {
        return Err(format!(
            "dump member {member_name:?} has an empty advisory id"
        ));
    }
    let record: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("dump member {member_name:?} is not JSON: {error}"))?;
    if record.get("id").and_then(Value::as_str) != Some(id.as_str()) {
        return Err(format!(
            "dump member {member_name:?} contains a record whose id does not match its name"
        ));
    }
    let modified = record
        .get("modified")
        .and_then(Value::as_str)
        .map(String::from);
    let mut packages = Vec::new();
    for affected in record
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let ecosystem = affected
            .pointer("/package/ecosystem")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = affected
            .pointer("/package/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if ecosystem.is_empty() || name.is_empty() {
            continue;
        }
        packages.push((
            ecosystem.to_string(),
            super::versioning::normalize_package(ecosystem, name),
        ));
    }
    Ok(ParsedMember {
        id,
        modified,
        record,
        packages,
    })
}

/// Ingest `ecosystems` into `db`. `note` receives human progress lines.
pub async fn update<F>(
    db: &mut AdvisoryDb,
    ecosystems: &[String],
    fetcher: &mut dyn DumpFetcher,
    mut note: F,
) -> Result<UpdateReport, String>
where
    F: FnMut(String),
{
    if ecosystems.is_empty() {
        return Err("no ecosystems selected; pass --ecosystem or use the defaults".into());
    }
    let mut reports = Vec::new();
    for ecosystem in ecosystems {
        note(format!("downloading the {ecosystem} dump…"));
        let zip_bytes = fetcher.fetch(ecosystem).await?;
        let zip_len = zip_bytes.len() as u64;

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&zip_bytes))
            .map_err(|error| format!("the {ecosystem} dump is not a readable zip: {error}"))?;
        if archive.len() > MAX_RECORDS_PER_ECOSYSTEM {
            return Err(format!(
                "resource limit: the {ecosystem} dump carries {} members (cap {MAX_RECORDS_PER_ECOSYSTEM})",
                archive.len()
            ));
        }
        let mut records = 0usize;
        for index in 0..archive.len() {
            let mut member = archive.by_index(index).map_err(|error| {
                format!("the {ecosystem} dump member {index} is unreadable: {error}")
            })?;
            let name = member.name().to_string();
            let mut bytes = Vec::new();
            member
                .by_ref()
                .take(MAX_RECORD_BYTES)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    format!("the {ecosystem} dump member {name:?} is unreadable: {error}")
                })?;
            if bytes.len() as u64 >= MAX_RECORD_BYTES {
                return Err(format!(
                    "resource limit: dump member {name:?} exceeds {} bytes",
                    MAX_RECORD_BYTES
                ));
            }
            let member = parse_member(&name, &bytes)?;
            if member.packages.is_empty() {
                // A record that affects no named package can never be
                // returned by a package query; index nothing for it.
                continue;
            }
            db.insert_record(
                &member.id,
                member.modified.as_deref(),
                &member.record,
                &member.packages,
            )?;
            records += 1;
        }
        note(format!(
            "{ecosystem}: {records} advisories from {} MiB of dump",
            zip_len / (1024 * 1024)
        ));
        reports.push(EcosystemReport {
            ecosystem: ecosystem.clone(),
            records,
            zip_bytes: zip_len,
        });
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    db.finish_update(ecosystems, now, now)?;
    let (total_advisories, total_packages) = db.counts()?;
    Ok(UpdateReport {
        ecosystems: reports,
        total_advisories,
        total_packages,
        built_at_ms: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureFetcher {
        dumps: std::collections::HashMap<String, Vec<u8>>,
    }

    impl DumpFetcher for FixtureFetcher {
        fn fetch<'a>(
            &'a mut self,
            ecosystem: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + 'a>>
        {
            Box::pin(async move {
                self.dumps
                    .get(ecosystem)
                    .cloned()
                    .ok_or_else(|| format!("no fixture dump for {ecosystem}"))
            })
        }
    }

    fn dump_zip(records: &[(String, String)]) -> Vec<u8> {
        // (member name, record body)
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in records {
            writer
                .start_file(name.clone(), zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut writer, body.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn advisory_json(id: &str, ecosystem: &str, package: &str) -> String {
        serde_json::json!({
            "id": id,
            "modified": "2024-05-01T00:00:00Z",
            "summary": "fixture advisory",
            "affected": [{
                "package": { "ecosystem": ecosystem, "name": package },
                "ranges": [{ "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}] }]
            }]
        })
        .to_string()
    }

    async fn run_update(
        dumps: std::collections::HashMap<String, Vec<u8>>,
        ecosystems: &[&str],
    ) -> Result<UpdateReport, String> {
        let mut db = AdvisoryDb::open_in_memory()?;
        let mut fetcher = FixtureFetcher { dumps };
        update(
            &mut db,
            &ecosystems.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            &mut fetcher,
            |_| {},
        )
        .await
    }

    #[test]
    fn ingests_records_and_indexes_every_affected_package() {
        let report = futures_block_on(run_update(
            std::collections::HashMap::from([(
                "npm".to_string(),
                dump_zip(&[
                    (
                        "GHSA-a.json".to_string(),
                        advisory_json("GHSA-a", "npm", "lodash"),
                    ),
                    (
                        "GHSA-b.json".to_string(),
                        advisory_json("GHSA-b", "npm", "lodash"),
                    ),
                    (
                        "GHSA-c.json".to_string(),
                        advisory_json("GHSA-c", "npm", "chalk"),
                    ),
                ]),
            )]),
            &["npm"],
        ))
        .unwrap();
        assert_eq!(report.ecosystems[0].records, 3);
        assert_eq!(report.total_advisories, 3);
        assert_eq!(report.total_packages, 2);
    }

    #[test]
    fn multi_ecosystem_records_are_indexed_under_every_package() {
        let multi = serde_json::json!({
            "id": "CVE-multi",
            "affected": [
                { "package": { "ecosystem": "npm", "name": "lodash" } },
                { "package": { "ecosystem": "PyPI", "name": "Django" } }
            ]
        })
        .to_string();
        let report = futures_block_on(run_update(
            std::collections::HashMap::from([(
                "npm".to_string(),
                dump_zip(&[("CVE-multi.json".to_string(), multi)]),
            )]),
            &["npm"],
        ))
        .unwrap();
        assert_eq!(report.total_packages, 2);
        // Coverage stays exactly what was downloaded, even though the record
        // indexed a PyPI package under npm's dump.
        let mut db = AdvisoryDb::open_in_memory().unwrap();
        let mut fetcher = FixtureFetcher {
            dumps: std::collections::HashMap::from([(
                "npm".to_string(),
                dump_zip(&[(
                    "CVE-multi.json".to_string(),
                    advisory_json("CVE-multi", "npm", "lodash"),
                )]),
            )]),
        };
        futures_block_on(update(&mut db, &["npm".to_string()], &mut fetcher, |_| {})).unwrap();
        assert_eq!(db.ecosystems().unwrap(), vec!["npm"]);
    }

    #[test]
    fn a_malformed_record_fails_the_update_by_name() {
        let error = futures_block_on(run_update(
            std::collections::HashMap::from([(
                "npm".to_string(),
                dump_zip(&[("not-json.json".to_string(), "{{{".to_string())]),
            )]),
            &["npm"],
        ))
        .unwrap_err();
        assert!(error.contains("not-json.json"), "{error}");
    }

    #[test]
    fn a_record_id_that_disagrees_with_its_member_name_fails() {
        let error = futures_block_on(run_update(
            std::collections::HashMap::from([(
                "npm".to_string(),
                dump_zip(&[(
                    "GHSA-a.json".to_string(),
                    advisory_json("GHSA-b", "npm", "lodash"),
                )]),
            )]),
            &["npm"],
        ))
        .unwrap_err();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn traversal_shaped_member_names_are_refused() {
        let error = futures_block_on(run_update(
            std::collections::HashMap::from([(
                "npm".to_string(),
                dump_zip(&[(
                    "../evil.json".to_string(),
                    advisory_json("evil", "npm", "x"),
                )]),
            )]),
            &["npm"],
        ))
        .unwrap_err();
        assert!(error.contains("not an advisory record name"), "{error}");
    }

    #[test]
    fn failed_ecosystems_do_not_widen_coverage() {
        // npm ingests fine; PyPI's fetch fails, so the coverage list must
        // stay empty rather than claim either ecosystem.
        let mut db = AdvisoryDb::open_in_memory().unwrap();
        let mut fetcher = FixtureFetcher {
            dumps: std::collections::HashMap::from([(
                "npm".to_string(),
                dump_zip(&[(
                    "GHSA-a.json".to_string(),
                    advisory_json("GHSA-a", "npm", "lodash"),
                )]),
            )]),
        };
        let error = futures_block_on(update(
            &mut db,
            &["npm".to_string(), "PyPI".to_string()],
            &mut fetcher,
            |_| {},
        ))
        .unwrap_err();
        assert!(error.contains("PyPI"), "{error}");
        assert!(
            db.ecosystems().unwrap().is_empty(),
            "a failed update must not advance coverage"
        );
        // The rows are inert extras: present, but unusable for coverage.
        assert_eq!(db.records_for("npm", "lodash").unwrap().len(), 1);
    }

    fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }
}
