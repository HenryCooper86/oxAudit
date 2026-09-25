//! SQLite-backed local OSV corpus.
//!
//! One row per (advisory, affected package) so a package lookup is a single
//! index seek. The full OSV record is stored zlib-compressed and parsed by the
//! shared OSV path at query time, which keeps a finding from the database and
//! a finding from the network identical in shape and evidence.
//!
//! Coverage is tracked separately from rows: `meta.ecosystems` lists the
//! ecosystems whose dumps were downloaded. A record from the npm dump that
//! also lists a PyPI package is indexed under both, but until the PyPI dump
//! has been downloaded PyPI queries must fail as uncovered, not answer from
//! partial data.

use std::io::{Read, Write};
use std::path::Path;

use rusqlite::{params, Connection};
use serde_json::Value;

pub const SCHEMA_VERSION: u64 = 1;
pub const SOURCE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";

const MAX_DECOMPRESSED_RECORD: usize = 64 * 1024 * 1024;

/// The connection sits in a `Mutex` so a scan can hold `&AdvisoryDb` across
/// an await: `rusqlite::Connection` is `Send` but not `Sync`.
pub struct AdvisoryDb {
    conn: std::sync::Mutex<Connection>,
}

#[derive(Debug)]
pub struct StoredRecord {
    /// The package name exactly as the OSV record spells it (queries arrive
    /// normalized; evidence is presented under the upstream spelling).
    pub package: String,
    pub record: Value,
}

fn compress(record: &Value) -> Result<Vec<u8>, String> {
    let raw = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder
        .write_all(&raw)
        .and_then(|_| encoder.finish())
        .map_err(|error| format!("advisory record compression failed: {error}"))
}

fn decompress(bytes: &[u8]) -> Result<Value, String> {
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(bytes)
        .take(MAX_DECOMPRESSED_RECORD as u64)
        .read_to_end(&mut raw)
        .map_err(|error| format!("advisory record decompression failed: {error}"))?;
    serde_json::from_slice(&raw).map_err(|error| format!("advisory record is not JSON: {error}"))
}

const LOCK_POISONED: &str = "advisory database lock poisoned";

impl AdvisoryDb {
    /// Open (creating if absent) an advisory database. The parent directory
    /// is the caller's responsibility; it must be private to the user.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|error| format!("cannot open an in-memory advisory database: {error}"))?;
        Self::init(conn)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.conn.lock().map_err(|_| LOCK_POISONED.to_string())
    }

    fn init(conn: Connection) -> Result<Self, String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS advisories (
                 id TEXT NOT NULL,
                 ecosystem TEXT NOT NULL,
                 package TEXT NOT NULL,
                 modified TEXT,
                 record BLOB NOT NULL,
                 PRIMARY KEY (id, ecosystem, package)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS advisories_by_package
                 ON advisories(ecosystem, package);",
        )
        .map_err(|error| format!("advisory database schema failed: {error}"))?;
        let db = Self {
            conn: std::sync::Mutex::new(conn),
        };
        let version = db.meta_u64("schemaVersion").unwrap_or(0);
        match version {
            0 => db.set_meta("schemaVersion", &SCHEMA_VERSION.to_string())?,
            v if v == SCHEMA_VERSION => {}
            other => {
                return Err(format!(
                    "advisory database schema version {other} is newer than this build understands ({SCHEMA_VERSION}); update oxAudit"
                ))
            }
        }
        Ok(db)
    }

    fn meta_u64(&self, key: &str) -> Option<u64> {
        self.meta_string(key).and_then(|value| value.parse().ok())
    }

    fn meta_string(&self, key: &str) -> Option<String> {
        let conn = self.lock().ok()?;
        conn.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .ok()
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|error| format!("advisory database metadata write failed: {error}"))?;
        Ok(())
    }

    /// The ecosystems whose dumps this database ingested — the coverage
    /// boundary for local queries.
    pub fn ecosystems(&self) -> Result<Vec<String>, String> {
        let raw = match self.meta_string("ecosystems") {
            Some(raw) => raw,
            None => return Ok(Vec::new()),
        };
        serde_json::from_str(&raw)
            .map_err(|error| format!("ecosystem metadata is invalid: {error}"))
    }

    pub fn source_url(&self) -> Result<String, String> {
        Ok(self
            .meta_string("source")
            .unwrap_or_else(|| SOURCE_URL.to_string()))
    }

    pub fn built_at_ms(&self) -> Option<u64> {
        self.meta_u64("builtAtMs")
    }

    pub fn updated_at_ms(&self) -> Option<u64> {
        self.meta_u64("updatedAtMs")
    }

    pub fn counts(&self) -> Result<(usize, usize), String> {
        let conn = self.lock()?;
        let advisories: i64 = conn
            .query_row("SELECT COUNT(DISTINCT id) FROM advisories", [], |row| {
                row.get(0)
            })
            .map_err(|error| format!("advisory count failed: {error}"))?;
        let packages: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT ecosystem || char(0) || package) FROM advisories",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("package count failed: {error}"))?;
        Ok((advisories as usize, packages as usize))
    }

    /// Insert one parsed record's rows inside the caller's transaction; see
    /// [`super::ingest`] for how records are sourced and bounded.
    pub(crate) fn insert_record(
        &mut self,
        id: &str,
        modified: Option<&str>,
        record: &Value,
        packages: &[(String, String)],
    ) -> Result<(), String> {
        let compressed = compress(record)?;
        let mut conn = self.lock()?;
        let tx = conn
            .transaction()
            .map_err(|error| format!("advisory write failed: {error}"))?;
        {
            let mut statement = tx
                .prepare(
                    "INSERT OR REPLACE INTO advisories (id, ecosystem, package, modified, record)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .map_err(|error| format!("advisory write failed: {error}"))?;
            for (ecosystem, package) in packages {
                statement
                    .execute(params![id, ecosystem, package, modified, compressed])
                    .map_err(|error| format!("advisory write failed: {error}"))?;
            }
        }
        tx.commit()
            .map_err(|error| format!("advisory write failed: {error}"))
    }

    /// Commit an update: merge the ingested ecosystems into the coverage list
    /// and stamp the build clocks.
    pub(crate) fn finish_update(
        &self,
        ecosystems: &[String],
        built_at_ms: u64,
        updated_at_ms: u64,
    ) -> Result<(), String> {
        let mut merged = self.ecosystems()?;
        for ecosystem in ecosystems {
            if !merged.iter().any(|existing| existing == ecosystem) {
                merged.push(ecosystem.clone());
            }
        }
        merged.sort();
        self.set_meta(
            "ecosystems",
            &serde_json::to_string(&merged).map_err(|e| e.to_string())?,
        )?;
        self.set_meta("source", SOURCE_URL)?;
        self.set_meta("builtAtMs", &built_at_ms.to_string())?;
        self.set_meta("updatedAtMs", &updated_at_ms.to_string())?;
        Ok(())
    }

    /// Every record that mentions `package` under `ecosystem`. `package` is
    /// normalized per ecosystem rules before the lookup.
    pub fn records_for(&self, ecosystem: &str, package: &str) -> Result<Vec<StoredRecord>, String> {
        let normalized = super::versioning::normalize_package(ecosystem, package);
        let conn = self.lock()?;
        let mut statement = conn
            .prepare("SELECT package, record FROM advisories WHERE ecosystem = ?1 AND package = ?2")
            .map_err(|error| format!("advisory lookup failed: {error}"))?;
        let rows = statement
            .query_map(params![ecosystem, normalized], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|error| format!("advisory lookup failed: {error}"))?;
        let mut out = Vec::new();
        for row in rows {
            let (stored_name, blob) =
                row.map_err(|error| format!("advisory lookup failed: {error}"))?;
            out.push(StoredRecord {
                package: stored_name,
                record: decompress(&blob)?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_record(id: &str, ecosystem: &str, package: &str) -> (Value, Vec<(String, String)>) {
        let record = serde_json::json!({
            "id": id,
            "summary": "test advisory",
            "affected": [{
                "package": { "ecosystem": ecosystem, "name": package },
                "ranges": [{ "type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}] }]
            }]
        });
        let packages = vec![(ecosystem.to_string(), package.to_string())];
        (record, packages)
    }

    #[test]
    fn round_trips_records_and_normalizes_lookups() {
        let mut db = AdvisoryDb::open_in_memory().unwrap();
        let (record, packages) = fixture_record("GHSA-1", "PyPI", "django");
        db.insert_record("GHSA-1", Some("2024-01-01T00:00:00Z"), &record, &packages)
            .unwrap();

        let rows = db.records_for("PyPI", "Django").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].package, "django");
        assert_eq!(rows[0].record["id"], "GHSA-1");
        assert_eq!(
            rows[0].record["affected"][0]["ranges"][0]["events"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        assert!(db.records_for("PyPI", "flask").unwrap().is_empty());
        assert!(db.records_for("npm", "django").unwrap().is_empty());
    }

    #[test]
    fn coverage_starts_empty_and_merges_across_updates() {
        let db = AdvisoryDb::open_in_memory().unwrap();
        assert!(db.ecosystems().unwrap().is_empty());

        db.finish_update(&["npm".into()], 100, 100).unwrap();
        assert_eq!(db.ecosystems().unwrap(), vec!["npm"]);

        db.finish_update(&["PyPI".into(), "npm".into()], 200, 200)
            .unwrap();
        assert_eq!(db.ecosystems().unwrap(), vec!["PyPI", "npm"]);
        assert_eq!(db.built_at_ms(), Some(200));
        assert_eq!(db.updated_at_ms(), Some(200));
    }

    #[test]
    fn counts_are_distinct_over_advisories_and_packages() {
        let mut db = AdvisoryDb::open_in_memory().unwrap();
        let (record, packages) = fixture_record("GHSA-1", "npm", "lodash");
        db.insert_record("GHSA-1", None, &record, &packages)
            .unwrap();
        let (record, packages) = fixture_record("GHSA-2", "npm", "lodash");
        db.insert_record("GHSA-2", None, &record, &packages)
            .unwrap();
        let (record, packages) = fixture_record("GHSA-2", "PyPI", "lodash");
        db.insert_record("GHSA-2", None, &record, &packages)
            .unwrap();

        let (advisories, packages) = db.counts().unwrap();
        assert_eq!(advisories, 2);
        assert_eq!(packages, 2);
    }

    #[test]
    fn a_newer_schema_version_is_refused_with_a_hint() {
        let db = AdvisoryDb::open_in_memory().unwrap();
        db.set_meta("schemaVersion", "99").unwrap();
        let error = match AdvisoryDb::init(db.conn.into_inner().expect("lock")) {
            Err(error) => error,
            Ok(_) => panic!("a newer database must not be silently downgraded"),
        };
        assert!(error.contains("update oxAudit"), "{error}");
    }
}
