use rusqlite::{params, Connection};

pub fn update(connection: &Connection, version: i64) -> rusqlite::Result<usize> {
    // A constant query with bound parameters is the correct pattern. The rule
    // matched `[^)]*` across the whole call, so the `+` inside params!
    // reported this as SQL injection.
    connection.execute(
        "UPDATE scan_runs SET fingerprint_version = ?2 WHERE id = ?1",
        params!["run-1", version + 1],
    )
}
