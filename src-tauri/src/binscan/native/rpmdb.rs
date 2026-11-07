//! rpm's package databases, read from image bytes: SQLite (`rpmdb.sqlite`)
//! and the older Berkeley DB `Packages` file.
//!
//! RHEL 9, Rocky and Alma 9, Fedora 33+ and Azure Linux keep the installed
//! package list in SQLite: one row per package in `Packages`, whose `blob`
//! column is the package's header. The database is deserialized into memory
//! (the extractor never writes image content to disk), opened read-only with
//! SQLite's defensive settings, and asked exactly one fixed question.

use oxaudit_parsers::rpm_header::{self, RpmPackage};

/// Largest single value SQLite will build while reading an rpm database.
const MAX_SQLITE_VALUE_BYTES: i32 = 32 * 1024 * 1024;
/// SQLite virtual-machine steps between progress checks, and how many checks
/// the read may take: about a hundred million steps, far beyond what reading
/// ten thousand real headers needs.
const SQLITE_STEPS_PER_CALL: std::ffi::c_int = 1000;
const MAX_SQLITE_PROGRESS_CALLS: u32 = 100_000;

/// Packages the database yielded, plus how many rows were unreadable.
#[derive(Debug, Default, PartialEq)]
pub struct RpmDatabase {
    pub packages: Vec<RpmPackage>,
    pub unreadable: usize,
    /// The read stopped at the per-database package cap.
    pub truncated: bool,
    /// Rows looked at, decoded or not: the cap counts every one, so rows
    /// that never decode cannot keep a read going.
    pub rows: usize,
}

/// Read every installed package. `gpg-pubkey` rows are rpm's record of
/// imported signing keys, not software, and are skipped.
pub fn read_sqlite(bytes: &[u8]) -> Result<RpmDatabase, String> {
    const HEADER: &[u8] = b"SQLite format 3\0";
    if bytes.len() < 100 || !bytes.starts_with(HEADER) {
        return Err("not an SQLite database".into());
    }
    // rpm runs its database in WAL mode, and an in-memory copy cannot open a
    // write-ahead log. Marking the copy as rollback-journal reads the main
    // file as checkpointed — which is all an image carries unless a `-wal`
    // sits beside it, and the scanner notes that case separately.
    let mut image = bytes.to_vec();
    image[18] = 1;
    image[19] = 1;

    let sqlite = |error: rusqlite::Error| error.to_string();
    let mut connection = rusqlite::Connection::open_in_memory().map_err(sqlite)?;
    connection
        .set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(sqlite)?;
    connection
        .deserialize_read_exact(rusqlite::MAIN_DB, image.as_slice(), image.len(), true)
        .map_err(sqlite)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(sqlite)?;
    // The file is attacker-shaped: `Packages` must be a real table (a view
    // can recurse forever), no value may be huge, and the whole read runs on
    // a bounded number of SQLite steps.
    connection
        .set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            MAX_SQLITE_VALUE_BYTES,
        )
        .map_err(sqlite)?;
    let kind: Option<String> = connection
        .query_row(
            "SELECT type FROM sqlite_schema WHERE name = 'Packages'",
            [],
            |row| row.get(0),
        )
        .ok();
    if kind.as_deref() != Some("table") {
        return Err("rpm database has no Packages table".into());
    }
    let mut budget = MAX_SQLITE_PROGRESS_CALLS;
    connection
        .progress_handler(
            SQLITE_STEPS_PER_CALL,
            Some(move || {
                budget = budget.saturating_sub(1);
                budget == 0
            }),
        )
        .map_err(sqlite)?;

    let mut statement = connection
        .prepare("SELECT blob FROM Packages")
        .map_err(sqlite)?;
    let mut rows = statement.query([]).map_err(sqlite)?;
    let mut database = RpmDatabase::default();
    while let Some(row) = rows.next().map_err(sqlite)? {
        let blob = row.get_ref(0).ok().and_then(|value| value.as_blob().ok());
        if !database.add(blob) {
            break;
        }
    }
    Ok(database)
}

/// Read every installed package from a Berkeley DB `Packages` file (RHEL 7
/// and 8, Rocky and Alma 8, Amazon Linux 2).
pub fn read_bdb(bytes: &[u8]) -> Result<RpmDatabase, String> {
    let (entries, skipped) =
        oxaudit_parsers::bdb_hash::entries_and_skipped(bytes).map_err(str::to_string)?;
    let mut database = RpmDatabase::default();
    // Values stored as duplicate sets are not decoded: count them as
    // unreadable so the scan's note says some packages were not read.
    database.unreadable += skipped;
    // Key 0 is rpm's next-instance counter, not a package.
    for (_, value) in entries.iter().filter(|(key, _)| key.as_slice() != [0u8; 4]) {
        if !database.add(Some(value)) {
            break;
        }
    }
    Ok(database)
}

impl RpmDatabase {
    /// Decode one stored header. Returns false once the package cap is hit.
    fn add(&mut self, blob: Option<&[u8]>) -> bool {
        if self.rows >= super::os_packages::MAX_PACKAGES_PER_DATABASE {
            self.truncated = true;
            return false;
        }
        self.rows += 1;
        match blob.map(rpm_header::parse_header_blob) {
            Some(Ok(package)) if package.name == "gpg-pubkey" => {}
            Some(Ok(package)) => self.packages.push(package),
            _ => self.unreadable += 1,
        }
        true
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn package(
        name: &str,
        epoch: Option<u32>,
        version: &str,
        release: &str,
        source_rpm: &str,
    ) -> RpmPackage {
        RpmPackage {
            name: name.into(),
            epoch,
            version: version.into(),
            release: release.into(),
            arch: Some("x86_64".into()),
            source_rpm: Some(source_rpm.into()),
        }
    }

    /// An rpm SQLite database holding these headers, as image bytes. rpm runs
    /// its database in WAL mode, which marks bytes 18 and 19 of the file
    /// header; the fixture does the same so reading has to cope with it.
    pub(crate) fn rpmdb_sqlite(blobs: &[Vec<u8>]) -> Vec<u8> {
        let mut connection = rusqlite::Connection::open_in_memory().expect("memory db");
        connection
            .execute_batch("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);")
            .expect("schema");
        for blob in blobs {
            connection
                .execute("INSERT INTO Packages (blob) VALUES (?1)", [blob])
                .expect("row");
        }
        let mut bytes = connection
            .serialize(rusqlite::MAIN_DB)
            .expect("serialize")
            .to_vec();
        bytes[18] = 2;
        bytes[19] = 2;
        bytes
    }

    #[test]
    fn reads_packages_from_an_rpmdb_sqlite() {
        let openssl = package(
            "openssl-libs",
            Some(1),
            "3.0.1",
            "1.el9",
            "openssl-3.0.1-1.el9.src.rpm",
        );
        let bash = package("bash", None, "5.1.8", "9.el9", "bash-5.1.8-9.el9.src.rpm");
        let key = package("gpg-pubkey", None, "fd431d51", "4ae0493b", "(none)");
        let bytes = rpmdb_sqlite(&[
            rpm_header::encode_header_blob(&openssl),
            rpm_header::encode_header_blob(&key),
            rpm_header::encode_header_blob(&bash),
        ]);
        let database = read_sqlite(&bytes).expect("database");
        assert_eq!(database.packages, vec![openssl, bash]);
        assert_eq!(database.unreadable, 0);
        assert!(!database.truncated);
    }

    #[test]
    fn reads_packages_from_a_berkeley_db_packages_file() {
        let openssl = package(
            "openssl-libs",
            Some(1),
            "1.1.1k",
            "7.el8_6",
            "openssl-1.1.1k-7.el8_6.src.rpm",
        );
        let key = package("gpg-pubkey", None, "fd431d51", "4ae0493b", "(none)");
        let file = oxaudit_parsers::bdb_hash::encode_for_tests(&[
            rpm_header::encode_header_blob(&key),
            rpm_header::encode_header_blob(&openssl),
            b"not a header".to_vec(),
        ]);
        let database = read_bdb(&file).expect("database");
        assert_eq!(database.packages, vec![openssl]);
        // The bad value counts; rpm's key-0 instance counter, which every
        // real Packages file carries, is bookkeeping and does not.
        assert_eq!(database.unreadable, 1);
        assert!(read_bdb(b"definitely not berkeley db").is_err());
    }

    #[test]
    fn unreadable_rows_are_counted_not_fatal() {
        let bash = package("bash", None, "5.1.8", "9.el9", "bash-5.1.8-9.el9.src.rpm");
        let bytes = rpmdb_sqlite(&[b"garbage".to_vec(), rpm_header::encode_header_blob(&bash)]);
        let database = read_sqlite(&bytes).expect("database");
        assert_eq!(database.packages, vec![bash]);
        assert_eq!(database.unreadable, 1);
    }

    #[test]
    fn a_packages_view_is_refused_rather_than_run() {
        // A crafted database can make `Packages` an endless recursive view.
        let mut connection = rusqlite::Connection::open_in_memory().expect("memory db");
        connection
            .execute_batch(
                "CREATE VIEW Packages AS WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x AS blob FROM c;",
            )
            .expect("schema");
        let bytes = connection
            .serialize(rusqlite::MAIN_DB)
            .expect("serialize")
            .to_vec();
        let started = std::time::Instant::now();
        assert!(read_sqlite(&bytes).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn every_row_counts_toward_the_package_cap() {
        let cap = super::super::os_packages::MAX_PACKAGES_PER_DATABASE;
        let rows: Vec<Vec<u8>> = (0..cap + 5).map(|_| b"x".to_vec()).collect();
        let database = read_sqlite(&rpmdb_sqlite(&rows)).expect("database");
        assert!(database.truncated);
        assert_eq!(database.unreadable, cap);
    }

    #[test]
    fn a_corrupt_or_foreign_database_is_an_error_not_a_panic() {
        assert!(read_sqlite(b"").is_err());
        assert!(read_sqlite(b"SQLite format 3\0 but not really").is_err());
        let mut bytes = rpmdb_sqlite(&[]);
        let tail = bytes.len() / 2;
        bytes.truncate(tail);
        assert!(
            read_sqlite(&bytes).is_err(),
            "a half-truncated database is an error"
        );
        // A real SQLite file without rpm's table.
        let mut other = rusqlite::Connection::open_in_memory().expect("memory db");
        other.execute_batch("CREATE TABLE t (x);").expect("schema");
        let other = other
            .serialize(rusqlite::MAIN_DB)
            .expect("serialize")
            .to_vec();
        assert!(read_sqlite(&other).is_err());
    }
}
