//! The installed rule-pack store: validated pack snapshots that scans apply.
//!
//! One SQLite file beside the findings database holds the packs a user
//! installed. The stored TOML *is* the snapshot: installing replaces any
//! previous snapshot of the same pack id, and enabled snapshots are
//! re-validated (parse, content hash, compile) every time a scan loads
//! them — a pack that no longer validates is skipped with its reason
//! rather than silently dropping rules or failing the scan. Runs record
//! the pack ids they applied; the snapshot hash rides the stored TOML and
//! the run's pack-sourced findings carry `pack/rule` ids either way.
//!
//! Installation reuses the exact validation the Rule Library's validate
//! command runs: schema, provenance, canonical content hash, regex
//! budgets, and — against the directory the pack file came from — fixture
//! hashes and path containment. Nothing executes; packs stay declarative.

use std::path::Path;
use std::sync::{Arc, Mutex};

use oxaudit_scanners::{CompiledRulePack, RulePack};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledRulePack {
    pub id: String,
    pub name: String,
    pub version: String,
    pub toml_sha256: String,
    pub content_sha256: String,
    pub rule_count: usize,
    pub engines: Vec<String>,
    pub enabled: bool,
    pub installed_at: String,
}

#[derive(Debug)]
pub struct RulePackStore {
    connection: Mutex<rusqlite::Connection>,
}

/// The states a scan's pack resolution can end in: the compiled packs that
/// will run, plus the ids that were skipped and why — surfaced to the scan
/// so degradation is visible instead of silent.
#[derive(Debug, Default)]
pub struct ResolvedPacks {
    pub packs: Vec<Arc<CompiledRulePack>>,
    pub skipped: Vec<(String, String)>,
}

impl RulePackStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create the rule-pack directory: {error}"))?;
        }
        let connection = rusqlite::Connection::open(path)
            .map_err(|error| format!("cannot open the rule-pack store: {error}"))?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS rule_packs (
                     id TEXT PRIMARY KEY,
                     name TEXT NOT NULL,
                     version TEXT NOT NULL,
                     toml_sha256 TEXT NOT NULL,
                     content_sha256 TEXT NOT NULL,
                     rule_count INTEGER NOT NULL,
                     engines TEXT NOT NULL,
                     enabled INTEGER NOT NULL,
                     installed_at TEXT NOT NULL,
                     toml TEXT NOT NULL
                 )",
            )
            .map_err(|error| format!("cannot initialize the rule-pack store: {error}"))?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// An in-memory store, for tests and previews.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, String> {
        let connection = rusqlite::Connection::open_in_memory()
            .map_err(|error| format!("cannot open an in-memory rule-pack store: {error}"))?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS rule_packs (
                     id TEXT PRIMARY KEY,
                     name TEXT NOT NULL,
                     version TEXT NOT NULL,
                     toml_sha256 TEXT NOT NULL,
                     content_sha256 TEXT NOT NULL,
                     rule_count INTEGER NOT NULL,
                     engines TEXT NOT NULL,
                     enabled INTEGER NOT NULL,
                     installed_at TEXT NOT NULL,
                     toml TEXT NOT NULL
                 )",
            )
            .map_err(|error| format!("cannot initialize the rule-pack store: {error}"))?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Validate and install (or replace) a pack from its TOML text. The
    /// fixture root is the directory the pack file was loaded from, matching
    /// the standalone validation command.
    pub fn install(
        &self,
        toml_text: &str,
        fixture_root: &Path,
        now: &str,
    ) -> Result<InstalledRulePack, String> {
        let pack = RulePack::parse_toml(toml_text).map_err(|error| error.to_string())?;
        pack.validate().map_err(|error| error.to_string())?;
        pack.validate_fixture_files(fixture_root)
            .map_err(|error| error.to_string())?;
        // Compiling here proves every regex builds before the pack is
        // stored; the same proof runs again on every scan that loads it.
        CompiledRulePack::compile(pack.clone()).map_err(|error| error.to_string())?;
        let metadata = &pack.pack;
        let toml_sha256 = format!("{:x}", Sha256::digest(toml_text.as_bytes()));
        let engines = pack
            .rules
            .iter()
            .map(|rule| {
                serde_json::to_value(rule.engine)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "unknown".into())
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let installed = InstalledRulePack {
            id: metadata.id.to_string(),
            name: metadata.name.clone(),
            version: metadata.version.clone(),
            toml_sha256,
            content_sha256: metadata.content_sha256.clone(),
            rule_count: pack.rules.len(),
            engines,
            enabled: true,
            installed_at: now.to_owned(),
        };
        let connection = self
            .connection
            .lock()
            .map_err(|_| "the rule-pack store is locked".to_owned())?;
        connection
            .execute(
                "INSERT OR REPLACE INTO rule_packs
                     (id, name, version, toml_sha256, content_sha256, rule_count,
                      engines, enabled, installed_at, toml)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    installed.id,
                    installed.name,
                    installed.version,
                    installed.toml_sha256,
                    installed.content_sha256,
                    installed.rule_count as i64,
                    serde_json::to_string(&installed.engines).unwrap_or_default(),
                    1_i64,
                    installed.installed_at,
                    toml_text,
                ],
            )
            .map_err(|error| format!("cannot install the rule pack: {error}"))?;
        Ok(installed)
    }

    pub fn list(&self) -> Vec<InstalledRulePack> {
        let Ok(connection) = self.connection.lock() else {
            return Vec::new();
        };
        let mut statement = match connection.prepare(
            "SELECT id, name, version, toml_sha256, content_sha256, rule_count,
                    engines, enabled, installed_at FROM rule_packs
             ORDER BY installed_at DESC, id",
        ) {
            Ok(statement) => statement,
            Err(_) => return Vec::new(),
        };
        let rows = statement
            .query_map([], |row| {
                Ok(InstalledRulePack {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    version: row.get(2)?,
                    toml_sha256: row.get(3)?,
                    content_sha256: row.get(4)?,
                    rule_count: row.get::<_, i64>(5)? as usize,
                    engines: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_default(),
                    enabled: row.get::<_, i64>(7)? != 0,
                    installed_at: row.get(8)?,
                })
            })
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default();
        rows
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "the rule-pack store is locked".to_owned())?;
        let changed = connection
            .execute(
                "UPDATE rule_packs SET enabled = ?1 WHERE id = ?2",
                rusqlite::params![i64::from(enabled), id],
            )
            .map_err(|error| format!("cannot update the rule pack: {error}"))?;
        if changed == 0 {
            return Err(format!("no installed rule pack with id {id}"));
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "the rule-pack store is locked".to_owned())?;
        let changed = connection
            .execute(
                "DELETE FROM rule_packs WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|error| format!("cannot remove the rule pack: {error}"))?;
        if changed == 0 {
            return Err(format!("no installed rule pack with id {id}"));
        }
        Ok(())
    }

    /// Compile every enabled pack for a scan, re-validating each snapshot.
    /// A pack that fails its re-validation is skipped with the reason; the
    /// scan runs with the packs that still hold.
    pub fn resolve_enabled(&self) -> ResolvedPacks {
        let mut resolved = ResolvedPacks::default();
        let Ok(connection) = self.connection.lock() else {
            return resolved;
        };
        let Ok(mut statement) =
            connection.prepare("SELECT id, toml FROM rule_packs WHERE enabled != 0 ORDER BY id")
        else {
            return resolved;
        };
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map(|rows| rows.filter_map(Result::ok).collect::<Vec<_>>())
            .unwrap_or_default();
        drop(statement);
        drop(connection);
        for (id, toml_text) in rows {
            match RulePack::parse_toml(&toml_text)
                .map_err(|error| error.to_string())
                .and_then(|pack| {
                    pack.validate().map_err(|error| error.to_string())?;
                    CompiledRulePack::compile(pack).map_err(|error| error.to_string())
                }) {
                Ok(compiled) => resolved.packs.push(Arc::new(compiled)),
                Err(reason) => resolved.skipped.push((id, reason)),
            }
        }
        resolved
    }
}

/// The managed Tauri state: the store when its database opened, or the
/// reason it did not. A failed store degrades to built-in-rules-only scans
/// rather than failing every scan.
pub struct RulePacksState {
    store: Option<RulePackStore>,
    error: Option<String>,
}

impl RulePacksState {
    pub fn available(store: RulePackStore) -> Self {
        Self {
            store: Some(store),
            error: None,
        }
    }

    pub fn unavailable(error: String) -> Self {
        Self {
            store: None,
            error: Some(error),
        }
    }

    pub fn store(&self) -> Result<&RulePackStore, String> {
        self.store.as_ref().ok_or_else(|| {
            self.error
                .clone()
                .unwrap_or_else(|| "the rule-pack store is unavailable".into())
        })
    }
}

/// Read, fully validate, and compile a pack file — the shared gate behind
/// both installation and ephemeral `--rule-pack-file` application. Fixtures
/// resolve against the file's own directory, exactly as the desktop's
/// validate command does.
pub fn compile_pack_file(path: &Path) -> Result<(CompiledRulePack, String), String> {
    const MAX_PACK_BYTES: u64 = 2 * 1024 * 1024;
    let path = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve the rule pack: {error}"))?;
    let metadata = path
        .metadata()
        .map_err(|error| format!("cannot inspect the rule pack: {error}"))?;
    if !metadata.is_file() {
        return Err("the selected rule pack is not a file".into());
    }
    if metadata.len() > MAX_PACK_BYTES {
        return Err("the rule pack exceeds the 2 MiB manifest limit".into());
    }
    let toml_text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read the rule pack: {error}"))?;
    let root = path
        .parent()
        .ok_or_else(|| "the rule pack has no containing directory".to_string())?;
    let pack = RulePack::parse_toml(&toml_text).map_err(|error| error.to_string())?;
    pack.validate().map_err(|error| error.to_string())?;
    pack.validate_fixture_files(root)
        .map_err(|error| error.to_string())?;
    let compiled = CompiledRulePack::compile(pack).map_err(|error| error.to_string())?;
    Ok((compiled, toml_text))
}

impl RulePackStore {
    /// Compile specific installed packs by id, re-validating each snapshot.
    /// Explicit selection applies the pack as stored; the enabled flag only
    /// governs default application (the desktop's every-scan behavior).
    pub fn resolve_selected(&self, ids: &[String]) -> ResolvedPacks {
        let mut resolved = ResolvedPacks::default();
        let Ok(connection) = self.connection.lock() else {
            return resolved;
        };
        let placeholders = std::iter::repeat("?")
            .take(ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT id, toml FROM rule_packs WHERE id IN ({placeholders})");
        let Ok(mut statement) = connection.prepare(&sql) else {
            return resolved;
        };
        let rows = statement
            .query_map(rusqlite::params_from_iter(ids.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map(|rows| rows.filter_map(Result::ok).collect::<Vec<_>>())
            .unwrap_or_default();
        drop(statement);
        drop(connection);
        let mut found = std::collections::BTreeSet::new();
        for (id, toml_text) in &rows {
            found.insert(id.clone());
            match RulePack::parse_toml(toml_text)
                .map_err(|error| error.to_string())
                .and_then(|pack| {
                    pack.validate().map_err(|error| error.to_string())?;
                    CompiledRulePack::compile(pack).map_err(|error| error.to_string())
                }) {
                Ok(compiled) => resolved.packs.push(std::sync::Arc::new(compiled)),
                Err(reason) => resolved.skipped.push((id.clone(), reason)),
            }
        }
        for id in ids {
            if !found.contains(id) {
                resolved
                    .skipped
                    .push((id.clone(), "not installed in this store".into()));
            }
        }
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxaudit_domain::CreationMethod;
    use oxaudit_scanners::{
        FixtureExpectation, RuleDefinition, RuleEngine, RulePackMetadata, RuleScope,
    };

    fn provenance(hash: &str) -> oxaudit_domain::Provenance {
        oxaudit_domain::Provenance {
            authors: vec!["oxAudit contributors".into()],
            source: "independent fixture".into(),
            license: "Apache-2.0".into(),
            creation_method: CreationMethod::IndependentlyDerived,
            content_sha256: hash.into(),
        }
    }

    fn fixture(id: &str, content: &str) -> FixtureExpectation {
        FixtureExpectation {
            id: id.into(),
            path: format!("{id}.txt"),
            sha256: hash_of(content),
            expected_values: Vec::new(),
        }
    }

    /// A real pack file on disk: fixtures must exist beside the TOML for
    /// installation to validate their hashes.
    fn write_pack(directory: &Path) -> String {
        let rules = vec![RuleDefinition {
            id: "source.eval".into(),
            version: "1".into(),
            title: "Dynamic evaluation".into(),
            description: "Finds eval calls".into(),
            recommendation: "Avoid eval on dynamic input.".into(),
            engine: RuleEngine::SourceRegex,
            severity: oxaudit_domain::Severity::High,
            scope: RuleScope {
                languages: vec!["javascript".into()],
                platforms: Vec::new(),
                architectures: Vec::new(),
                file_extensions: Vec::new(),
            },
            pattern: r"dangerousEval\(([^)]+)\)".into(),
            classifications: Vec::new(),
            provenance: provenance(&"b".repeat(64)),
            positive_fixtures: vec![fixture("positive", "positive fixture\n")],
            negative_fixtures: vec![fixture("negative", "negative fixture\n")],
        }];
        let hash = RulePack::computed_content_sha256(&rules).unwrap();
        let pack = RulePack {
            pack: RulePackMetadata {
                schema_version: 1,
                id: oxaudit_domain::RulePackId::parse("rulepack.test").unwrap(),
                name: "Test rules".into(),
                version: "1.0.0".into(),
                minimum_oxaudit_version: "0.1.0".into(),
                content_sha256: hash.clone(),
                provenance: provenance(&hash),
            },
            rules,
        };
        // Round-trip through the pack's own serializer: the stored snapshot
        // is exactly the format parse expects.
        let toml_text = toml::to_string(&pack).unwrap();
        std::fs::write(directory.join("positive.txt"), "positive fixture\n").unwrap();
        std::fs::write(directory.join("negative.txt"), "negative fixture\n").unwrap();
        std::fs::write(directory.join("pack.toml"), &toml_text).unwrap();
        toml_text
    }

    fn hash_of(content: &str) -> String {
        format!("{:x}", Sha256::digest(content.as_bytes()))
    }

    #[test]
    fn install_validates_listens_and_resolves_enabled_packs() {
        let directory = tempfile::tempdir().unwrap();
        let toml_text = write_pack(directory.path());
        let store = RulePackStore::open(&directory.path().join("packs.sqlite3")).unwrap();

        let installed = store
            .install(&toml_text, directory.path(), "2026-09-24T00:00:00Z")
            .expect("valid pack installs");
        assert_eq!(installed.id, "rulepack.test");
        assert_eq!(installed.rule_count, 1);
        assert!(installed.enabled);

        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].engines, vec!["source_regex".to_string()]);

        let resolved = store.resolve_enabled();
        assert_eq!(resolved.packs.len(), 1);
        assert!(resolved.skipped.is_empty());
        assert_eq!(resolved.packs[0].metadata().id.to_string(), "rulepack.test");

        store.set_enabled("rulepack.test", false).unwrap();
        assert!(!store.list()[0].enabled);
        assert!(store.resolve_enabled().packs.is_empty());

        store.remove("rulepack.test").unwrap();
        assert!(store.list().is_empty());
        assert!(store.remove("rulepack.test").is_err());
    }

    #[test]
    fn a_tampered_snapshot_is_skipped_with_its_reason_not_applied() {
        let directory = tempfile::tempdir().unwrap();
        let toml_text = write_pack(directory.path());
        let store = RulePackStore::open(&directory.path().join("packs.sqlite3")).unwrap();
        store
            .install(&toml_text, directory.path(), "2026-09-24T00:00:00Z")
            .unwrap();

        // Corrupt the stored snapshot the way a truncated write or an edit
        // outside oxAudit would.
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute("UPDATE rule_packs SET toml = 'not toml at all'", [])
                .unwrap();
        }
        let resolved = store.resolve_enabled();
        assert!(resolved.packs.is_empty());
        assert_eq!(resolved.skipped.len(), 1);
        assert!(resolved.skipped[0].0 == "rulepack.test");
        assert!(!resolved.skipped[0].1.is_empty());
    }

    #[test]
    fn an_invalid_pack_never_installs() {
        let directory = tempfile::tempdir().unwrap();
        let store = RulePackStore::open(&directory.path().join("packs.sqlite3")).unwrap();
        let error = store
            .install("[pack]\n", directory.path(), "2026-09-24T00:00:00Z")
            .unwrap_err();
        assert!(store.list().is_empty(), "nothing stored: {error}");
    }
}
