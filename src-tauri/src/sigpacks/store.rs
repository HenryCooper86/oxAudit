//! The signature pack store: files on disk plus a `signature_packs` table.

use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::source::{self, PackFile, MAX_FILES, MAX_FILE_BYTES};
use super::{PackKind, PackSkip};

const MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LICENSE_CHARS: usize = 200;
const MAX_FIELD_CHARS: usize = 500;

/// Metadata the user supplies at import.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackMetadata {
    pub name: String,
    pub license: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub authors: Option<String>,
}

/// What an import would do, computed without writing anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackPreview {
    pub kind: PackKind,
    pub file_count: usize,
    pub ignored_count: usize,
    pub rule_count: usize,
    pub skipped: Vec<PackSkip>,
    pub content_sha256: String,
    pub detected_license: Option<String>,
    pub total_bytes: u64,
    /// Nuclei packs: supported templates per protocol. `None` for YARA packs.
    pub protocols: Option<PackProtocols>,
    /// Nuclei packs: templates that load but that oxAudit cannot evaluate
    /// (each is in `skipped` with its reasons).
    pub not_evaluated_count: usize,
}

/// How many supported templates of a Nuclei pack use each protocol. A
/// template with two protocols counts once under each.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackProtocols {
    pub http: usize,
    pub dns: usize,
    pub tcp: usize,
    pub ssl: usize,
    pub file: usize,
}

/// A pack as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledSigPack {
    pub id: String,
    pub kind: PackKind,
    pub name: String,
    pub version: String,
    pub license: String,
    pub source: String,
    pub authors: String,
    pub content_sha256: String,
    pub file_count: usize,
    pub rule_count: usize,
    pub skipped: Vec<PackSkip>,
    pub enabled: bool,
    pub installed_at: String,
    /// Nuclei packs: supported templates per protocol. `None` for YARA packs.
    pub protocols: Option<PackProtocols>,
    pub not_evaluated_count: usize,
}

/// A pack whose files were re-read and verified against its manifest.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(feature = "yara", feature = "templates")), allow(dead_code))]
pub struct ResolvedPack {
    pub record: InstalledSigPack,
    pub files: Vec<PackFile>,
}

/// The outcome of resolving packs for a scan: the verified ones, plus every
/// pack that was left out and why. Callers surface `skipped` as run warnings.
#[derive(Debug, Default)]
pub struct ResolvedSigPacks {
    pub packs: Vec<ResolvedPack>,
    /// `(pack id, reason)`.
    pub skipped: Vec<(String, String)>,
}

/// The per-kind counts kept in the `stats_json` column.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct PackStats {
    protocols: Option<PackProtocols>,
    not_evaluated_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    files: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManifestEntry {
    path: String,
    sha256: String,
    bytes: u64,
}

struct Inspection {
    rule_count: usize,
    skipped: Vec<PackSkip>,
    /// YAML files that are clearly not templates (no top-level `id`).
    ignored: usize,
    protocols: Option<PackProtocols>,
    not_evaluated_count: usize,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn manifest_entries(files: &[PackFile]) -> Vec<ManifestEntry> {
    let mut entries: Vec<ManifestEntry> = files
        .iter()
        .map(|file| ManifestEntry {
            path: file.path.clone(),
            sha256: sha256_hex(file.text.as_bytes()),
            bytes: file.text.len() as u64,
        })
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries
}

/// SHA-256 over the sorted manifest lines (`<sha256>  <path>\n`).
fn content_hash(entries: &[ManifestEntry]) -> String {
    let mut sorted: Vec<&ManifestEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut hasher = Sha256::new();
    for entry in sorted {
        hasher.update(format!("{}  {}\n", entry.sha256, entry.path).as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Compile every YARA source in the pack to learn how many rules it holds
/// and which files do not compile.
#[cfg(feature = "yara")]
fn inspect_yara_sources(files: &[PackFile]) -> Result<Inspection, String> {
    let sources = rule_sources(files);
    let set = oxaudit_yara::RuleSet::compile(&sources, &oxaudit_yara::CompileLimits::default())
        .map_err(|error| error.to_string())?;
    Ok(Inspection {
        rule_count: set.rules().len(),
        skipped: set
            .skipped()
            .iter()
            .map(|skip| PackSkip {
                file: skip.origin.clone(),
                line: skip.line,
                message: skip.message.clone(),
            })
            .collect(),
        ignored: 0,
        protocols: None,
        not_evaluated_count: 0,
    })
}

#[cfg(not(feature = "yara"))]
fn inspect_yara_sources(_files: &[PackFile]) -> Result<Inspection, String> {
    Err(
        "this build of oxAudit has no YARA engine, so YARA packs cannot be validated or imported"
            .into(),
    )
}

/// Load every YAML file as a Nuclei template. `rule_count` is the number of
/// distinct templates that load and that oxAudit can evaluate; every file that
/// fails to load, every template it cannot evaluate, and every repeated id is
/// listed with its reason. YAML with no top-level `id` is not a template at
/// all (workflows, configs, CI files) and is only counted as ignored.
#[cfg(feature = "templates")]
fn inspect_nuclei_sources(files: &[PackFile]) -> Result<Inspection, String> {
    use oxaudit_nuclei::{Protocol, Support};
    let loaded = super::nuclei::load_templates(files);
    let mut skipped: Vec<PackSkip> = Vec::new();
    for (file, message) in &loaded.errors {
        skipped.push(PackSkip {
            file: file.clone(),
            line: None,
            message: message.clone(),
        });
    }
    for (file, id, first) in &loaded.duplicates {
        skipped.push(PackSkip {
            file: file.clone(),
            line: None,
            message: format!("duplicate template id `{id}`; the copy in {first} is used"),
        });
    }
    let mut rule_count = 0usize;
    let mut not_evaluated_count = 0usize;
    let mut protocols = PackProtocols::default();
    for entry in &loaded.templates {
        match entry.template.support() {
            Support::Supported => {
                rule_count += 1;
                for protocol in entry.template.protocols() {
                    match protocol {
                        Protocol::Http => protocols.http += 1,
                        Protocol::Dns => protocols.dns += 1,
                        Protocol::Tcp => protocols.tcp += 1,
                        Protocol::Ssl => protocols.ssl += 1,
                        Protocol::File => protocols.file += 1,
                    }
                }
            }
            Support::NotEvaluated(reasons) => {
                not_evaluated_count += 1;
                skipped.push(PackSkip {
                    file: entry.file.clone(),
                    line: None,
                    message: format!("not evaluated: {}", reasons.join("; ")),
                });
            }
        }
    }
    skipped.sort_by(|a, b| a.file.cmp(&b.file));
    Ok(Inspection {
        rule_count,
        skipped,
        ignored: loaded.ignored,
        protocols: Some(protocols),
        not_evaluated_count,
    })
}

#[cfg(not(feature = "templates"))]
fn inspect_nuclei_sources(_files: &[PackFile]) -> Result<Inspection, String> {
    Err(
        "this build of oxAudit has no template engine, so Nuclei packs cannot be validated or imported"
            .into(),
    )
}

fn inspect(kind: PackKind, files: &[PackFile]) -> Result<Inspection, String> {
    match kind {
        PackKind::Yara => inspect_yara_sources(files),
        PackKind::Nuclei => inspect_nuclei_sources(files),
    }
}

/// YARA rule sources for a set of pack files, namespaced by relative path.
#[cfg(feature = "yara")]
fn rule_sources(files: &[PackFile]) -> Vec<oxaudit_yara::RuleSource> {
    files
        .iter()
        .map(|file| oxaudit_yara::RuleSource {
            namespace: file.path.clone(),
            origin: file.path.clone(),
            text: file.text.clone(),
        })
        .collect()
}

/// Read and check an import source without writing anything.
pub fn validate_pack(kind: PackKind, source: &Path) -> Result<PackPreview, String> {
    let collected = source::collect(kind, source)?;
    preview_of(kind, &collected).map(|(preview, _)| preview)
}

fn preview_of(
    kind: PackKind,
    collected: &source::CollectedPack,
) -> Result<(PackPreview, Inspection), String> {
    let inspection = inspect(kind, &collected.files)?;
    let entries = manifest_entries(&collected.files);
    let mut skipped = collected.skipped.clone();
    skipped.extend(inspection.skipped.iter().cloned());
    Ok((
        PackPreview {
            kind,
            file_count: collected.files.len(),
            ignored_count: collected.ignored + inspection.ignored,
            rule_count: inspection.rule_count,
            skipped,
            content_sha256: content_hash(&entries),
            detected_license: collected.detected_license.clone(),
            total_bytes: collected.total_bytes,
            protocols: inspection.protocols,
            not_evaluated_count: inspection.not_evaluated_count,
        },
        inspection,
    ))
}

/// A valid pack id: `^[a-z0-9][a-z0-9._-]{0,63}$`.
pub fn is_valid_pack_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in name.trim().to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_' {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    let mut slug: String = trimmed.chars().take(50).collect();
    slug = slug
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_owned();
    if slug.is_empty() {
        "pack".into()
    } else {
        slug
    }
}

/// Pack id: slug of the name plus the first 12 hex characters of the
/// content hash, so the same name with different content is a different pack.
pub fn pack_id_for(name: &str, content_sha256: &str) -> String {
    format!("{}-{}", slug(name), &content_sha256[..12])
}

fn check_metadata(meta: &PackMetadata) -> Result<(), String> {
    if meta.name.trim().is_empty() {
        return Err("a pack name is required".into());
    }
    if meta.name.chars().count() > MAX_FIELD_CHARS {
        return Err(format!(
            "the pack name is over {MAX_FIELD_CHARS} characters"
        ));
    }
    if meta.license.trim().is_empty() {
        return Err(
            "a licence is required; record the licence the pack's rules are published under".into(),
        );
    }
    if meta.license.chars().count() > MAX_LICENSE_CHARS {
        return Err(format!(
            "the licence is over {MAX_LICENSE_CHARS} characters"
        ));
    }
    for (label, value) in [
        ("version", &meta.version),
        ("source", &meta.source),
        ("authors", &meta.authors),
    ] {
        if value
            .as_deref()
            .is_some_and(|v| v.chars().count() > MAX_FIELD_CHARS)
        {
            return Err(format!("the {label} is over {MAX_FIELD_CHARS} characters"));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct SigPackStore {
    connection: Mutex<rusqlite::Connection>,
    root: PathBuf,
}

const SELECT_COLUMNS: &str = "id, kind, name, version, license, source, authors, content_sha256, \
     file_count, rule_count, skipped_json, enabled, installed_at, stats_json";

impl SigPackStore {
    /// Open the table in `db_path` (the rule-pack database) and keep pack
    /// files in a `sigpacks` directory beside it.
    pub fn open(db_path: &Path) -> Result<Self, String> {
        let root = db_path
            .parent()
            .map(|parent| parent.join("sigpacks"))
            .unwrap_or_else(|| PathBuf::from("sigpacks"));
        Self::open_with_root(db_path, &root)
    }

    pub fn open_with_root(db_path: &Path, root: &Path) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create the signature-pack directory: {error}"))?;
        }
        let connection = rusqlite::Connection::open(db_path)
            .map_err(|error| format!("cannot open the signature-pack store: {error}"))?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS signature_packs (
                     id TEXT PRIMARY KEY,
                     kind TEXT NOT NULL,
                     name TEXT NOT NULL,
                     version TEXT NOT NULL,
                     license TEXT NOT NULL,
                     source TEXT NOT NULL,
                     authors TEXT NOT NULL,
                     content_sha256 TEXT NOT NULL,
                     file_count INTEGER NOT NULL,
                     rule_count INTEGER NOT NULL,
                     skipped_json TEXT NOT NULL,
                     enabled INTEGER NOT NULL,
                     installed_at TEXT NOT NULL,
                     stats_json TEXT NOT NULL DEFAULT '{}'
                 )",
            )
            .map_err(|error| format!("cannot initialize the signature-pack store: {error}"))?;
        // A table created before `stats_json` existed gets the column here.
        let has_stats: bool = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('signature_packs') WHERE name = 'stats_json'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .map_err(|error| format!("cannot initialize the signature-pack store: {error}"))?;
        if !has_stats {
            connection
                .execute(
                    "ALTER TABLE signature_packs ADD COLUMN stats_json TEXT NOT NULL DEFAULT '{}'",
                    [],
                )
                .map_err(|error| format!("cannot upgrade the signature-pack store: {error}"))?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
            root: root.to_owned(),
        })
    }

    fn pack_dir(&self, kind: PackKind, id: &str) -> Result<PathBuf, String> {
        if !is_valid_pack_id(id) {
            return Err(format!("{id:?} is not a valid signature pack id"));
        }
        Ok(self.root.join(kind.as_str()).join(id))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, String> {
        self.connection
            .lock()
            .map_err(|_| "the signature-pack store is locked".to_owned())
    }

    /// Import a pack. Installing identical content again returns the
    /// existing pack unchanged, provided its files still verify; a damaged
    /// copy is replaced.
    pub fn install(
        &self,
        kind: PackKind,
        source: &Path,
        meta: &PackMetadata,
        now: &str,
    ) -> Result<InstalledSigPack, String> {
        check_metadata(meta)?;
        let collected = source::collect(kind, source)?;
        let (preview, inspection) = preview_of(kind, &collected)?;
        let id = pack_id_for(&meta.name, &preview.content_sha256);
        if !is_valid_pack_id(&id) {
            return Err("could not derive a valid pack id from the name".into());
        }
        if let Some(existing) = self.get(&id)? {
            if self.read_verified(&existing).is_ok() {
                return Ok(existing);
            }
        }

        let final_dir = self.pack_dir(kind, &id)?;
        let kind_dir = self.root.join(kind.as_str());
        std::fs::create_dir_all(&kind_dir)
            .map_err(|error| format!("cannot create the pack directory: {error}"))?;
        let tmp = kind_dir.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        let written = write_pack_dir(&tmp, &collected.files);
        if let Err(error) = written {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(error);
        }
        if final_dir.exists() {
            if let Err(error) = std::fs::remove_dir_all(&final_dir) {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err(format!("cannot replace the damaged pack copy: {error}"));
            }
        }
        if let Err(error) = std::fs::rename(&tmp, &final_dir) {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(format!("cannot place the pack files: {error}"));
        }

        let installed = InstalledSigPack {
            id,
            kind,
            name: meta.name.trim().to_owned(),
            version: meta.version.clone().unwrap_or_default().trim().to_owned(),
            license: meta.license.trim().to_owned(),
            source: meta.source.clone().unwrap_or_default().trim().to_owned(),
            authors: meta.authors.clone().unwrap_or_default().trim().to_owned(),
            content_sha256: preview.content_sha256.clone(),
            file_count: preview.file_count,
            rule_count: inspection.rule_count,
            skipped: preview.skipped.clone(),
            enabled: true,
            installed_at: now.to_owned(),
            protocols: inspection.protocols,
            not_evaluated_count: inspection.not_evaluated_count,
        };
        let skipped_json = oxaudit_parsers::stable_json::to_string(&installed.skipped)
            .map_err(|error| format!("cannot record skipped files: {error}"))?;
        let stats_json = oxaudit_parsers::stable_json::to_string(&PackStats {
            protocols: installed.protocols,
            not_evaluated_count: installed.not_evaluated_count,
        })
        .map_err(|error| format!("cannot record pack statistics: {error}"))?;
        let inserted = self.lock().and_then(|connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO signature_packs
                         (id, kind, name, version, license, source, authors, content_sha256,
                          file_count, rule_count, skipped_json, enabled, installed_at, stats_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    rusqlite::params![
                        installed.id,
                        kind.as_str(),
                        installed.name,
                        installed.version,
                        installed.license,
                        installed.source,
                        installed.authors,
                        installed.content_sha256,
                        installed.file_count as i64,
                        installed.rule_count as i64,
                        skipped_json,
                        1_i64,
                        installed.installed_at,
                        stats_json,
                    ],
                )
                .map_err(|error| format!("cannot install the signature pack: {error}"))
        });
        if let Err(error) = inserted {
            let _ = std::fs::remove_dir_all(&final_dir);
            return Err(error);
        }
        Ok(installed)
    }

    fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstalledSigPack> {
        let conversion = |index: usize, error: String| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                error.into(),
            )
        };
        let kind: String = row.get(1)?;
        let count = |index: usize| -> rusqlite::Result<usize> {
            let value = row.get::<_, i64>(index)?;
            usize::try_from(value)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
        };
        let stats: PackStats = serde_json::from_str(&row.get::<_, String>(13)?)
            .map_err(|error| conversion(13, error.to_string()))?;
        Ok(InstalledSigPack {
            id: row.get(0)?,
            kind: PackKind::parse(&kind).map_err(|error| conversion(1, error))?,
            name: row.get(2)?,
            version: row.get(3)?,
            license: row.get(4)?,
            source: row.get(5)?,
            authors: row.get(6)?,
            content_sha256: row.get(7)?,
            file_count: count(8)?,
            rule_count: count(9)?,
            skipped: serde_json::from_str(&row.get::<_, String>(10)?)
                .map_err(|error| conversion(10, error.to_string()))?,
            enabled: row.get::<_, i64>(11)? != 0,
            installed_at: row.get(12)?,
            protocols: stats.protocols,
            not_evaluated_count: stats.not_evaluated_count,
        })
    }

    fn get(&self, id: &str) -> Result<Option<InstalledSigPack>, String> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM signature_packs WHERE id = ?1"
            ))
            .map_err(|error| format!("cannot read signature packs: {error}"))?;
        let mut rows = statement
            .query_map([id], Self::row)
            .map_err(|error| format!("cannot read signature packs: {error}"))?;
        rows.next()
            .transpose()
            .map_err(|error| format!("cannot read signature packs: {error}"))
    }

    pub fn list(&self) -> Result<Vec<InstalledSigPack>, String> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM signature_packs ORDER BY installed_at DESC, id"
            ))
            .map_err(|error| format!("cannot read signature packs: {error}"))?;
        let rows = statement
            .query_map([], Self::row)
            .map_err(|error| format!("cannot read signature packs: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot read signature packs: {error}"))
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), String> {
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE signature_packs SET enabled = ?1 WHERE id = ?2",
                rusqlite::params![i64::from(enabled), id],
            )
            .map_err(|error| format!("cannot update the signature pack: {error}"))?;
        if changed == 0 {
            return Err(format!("no installed signature pack with id {id}"));
        }
        Ok(())
    }

    /// Delete the pack's row and its files. Past runs keep the pack id,
    /// licence and hash they recorded.
    pub fn remove(&self, id: &str) -> Result<(), String> {
        let Some(record) = self.get(id)? else {
            return Err(format!("no installed signature pack with id {id}"));
        };
        let dir = self.pack_dir(record.kind, &record.id)?;
        {
            let connection = self.lock()?;
            connection
                .execute("DELETE FROM signature_packs WHERE id = ?1", [id])
                .map_err(|error| format!("cannot remove the signature pack: {error}"))?;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "the pack was removed from the list but its files could not be deleted ({}): {error}",
                dir.display()
            )),
        }
    }

    /// Re-read the packs of `kind` for a scan: every enabled pack when `ids`
    /// is `None`, otherwise exactly the named ones (enabled or not). Each
    /// pack's files are re-verified against its manifest and the manifest
    /// against the stored content hash; a pack that fails is reported in
    /// `skipped` with the reason and not applied.
    pub fn resolve(
        &self,
        kind: PackKind,
        ids: Option<&[String]>,
    ) -> Result<ResolvedSigPacks, String> {
        let mut resolved = ResolvedSigPacks::default();
        let mut records: Vec<InstalledSigPack> = Vec::new();
        match ids {
            None => {
                records.extend(
                    self.list()?
                        .into_iter()
                        .filter(|pack| pack.kind == kind && pack.enabled),
                );
                records.sort_by(|a, b| a.id.cmp(&b.id));
            }
            Some(ids) => {
                let mut seen = std::collections::BTreeSet::new();
                for id in ids {
                    if !seen.insert(id.clone()) {
                        continue;
                    }
                    match self.get(id) {
                        Ok(Some(pack)) if pack.kind == kind => records.push(pack),
                        Ok(Some(pack)) => resolved.skipped.push((
                            id.clone(),
                            format!(
                                "is a {} pack, not a {} pack",
                                pack.kind.as_str(),
                                kind.as_str()
                            ),
                        )),
                        Ok(None) => resolved
                            .skipped
                            .push((id.clone(), "not installed in this store".into())),
                        Err(error) => resolved.skipped.push((id.clone(), error)),
                    }
                }
            }
        }
        for record in records {
            match self.read_verified(&record) {
                Ok(files) => resolved.packs.push(ResolvedPack { record, files }),
                Err(reason) => resolved.skipped.push((record.id.clone(), reason)),
            }
        }
        Ok(resolved)
    }

    fn read_verified(&self, record: &InstalledSigPack) -> Result<Vec<PackFile>, String> {
        let dir = self.pack_dir(record.kind, &record.id)?;
        let manifest_path = dir.join(MANIFEST_FILE);
        let manifest_bytes = read_regular(&manifest_path, MAX_MANIFEST_BYTES)
            .map_err(|error| format!("the pack manifest is unreadable: {error}"))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| format!("the pack manifest is damaged: {error}"))?;
        if manifest.schema_version != 1 {
            return Err("the pack manifest has an unsupported schema version".into());
        }
        if manifest.files.len() > MAX_FILES {
            return Err("the pack manifest lists too many files".into());
        }
        if content_hash(&manifest.files) != record.content_sha256 {
            return Err(
                "the pack manifest no longer matches the content hash recorded at import; the pack was modified"
                    .into(),
            );
        }
        if manifest.files.len() != record.file_count {
            return Err(
                "the pack manifest lists a different number of files than was imported".into(),
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut files = Vec::with_capacity(manifest.files.len());
        for entry in &manifest.files {
            if !seen.insert(entry.path.as_str()) {
                return Err(format!("the pack manifest lists {} twice", entry.path));
            }
            let relative = Path::new(&entry.path);
            let safe = !entry.path.is_empty()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)));
            if !safe {
                return Err(format!(
                    "the pack manifest has an unsafe path {:?}",
                    entry.path
                ));
            }
            let bytes = read_regular(&dir.join(relative), MAX_FILE_BYTES)
                .map_err(|error| format!("{}: {error}", entry.path))?;
            if sha256_hex(&bytes) != entry.sha256 {
                return Err(format!(
                    "{} no longer matches the hash recorded at import; the file was modified",
                    entry.path
                ));
            }
            let text = String::from_utf8(bytes)
                .map_err(|_| format!("{} is not valid UTF-8", entry.path))?;
            files.push(PackFile {
                path: entry.path.clone(),
                text,
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(files)
    }
}

/// Read a regular file (never through a symlink), bounded.
fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !meta.file_type().is_file() {
        return Err("is not a regular file".into());
    }
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("is larger than its size limit".into());
    }
    Ok(bytes)
}

fn write_pack_dir(dir: &Path, files: &[PackFile]) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("cannot create the pack directory: {error}"))?;
    for file in files {
        let target = dir.join(&file.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot write the pack files: {error}"))?;
        }
        std::fs::write(&target, file.text.as_bytes())
            .map_err(|error| format!("cannot write {}: {error}", file.path))?;
    }
    let manifest = Manifest {
        schema_version: 1,
        files: manifest_entries(files),
    };
    let json = oxaudit_parsers::stable_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("cannot write the manifest: {error}"))?;
    std::fs::write(dir.join(MANIFEST_FILE), json)
        .map_err(|error| format!("cannot write the manifest: {error}"))
}

/// The managed state: the store when its database opened, or the reason it
/// did not.
pub struct SigPacksState {
    store: Option<std::sync::Arc<SigPackStore>>,
    error: Option<String>,
}

impl SigPacksState {
    pub fn available(store: SigPackStore) -> Self {
        Self {
            store: Some(std::sync::Arc::new(store)),
            error: None,
        }
    }

    pub fn unavailable(error: String) -> Self {
        Self {
            store: None,
            error: Some(error),
        }
    }

    pub fn store(&self) -> Result<&SigPackStore, String> {
        self.shared().map(|store| &**store)
    }

    /// The store as a shared handle, for work moved to a blocking thread.
    pub fn shared(&self) -> Result<&std::sync::Arc<SigPackStore>, String> {
        self.store.as_ref().ok_or_else(|| {
            self.error
                .clone()
                .unwrap_or_else(|| "the signature-pack store is unavailable".into())
        })
    }

    /// Open the store beside the rule-pack database at `db_path`.
    pub fn open_beside(db_path: &Path) -> Self {
        match SigPackStore::open(db_path) {
            Ok(store) => Self::available(store),
            Err(error) => {
                log::warn!("signature-pack store unavailable: {error}");
                Self::unavailable(error)
            }
        }
    }
}
