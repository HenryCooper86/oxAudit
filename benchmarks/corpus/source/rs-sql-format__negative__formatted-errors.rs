use rusqlite::{params, Connection, Statement};

pub fn execute(_on_progress: std::sync::Arc<dyn Fn(String) + Send + Sync>) {}

pub fn update(connection: &Connection, name: &str) -> Result<usize, String> {
    connection
        .execute("UPDATE users SET name = ?1", params![format!("{name}")])
        .map_err(|error| format!("database operation failed: {error}"))
}

pub fn execute_bound(statement: &mut Statement<'_>, name: &str) -> Result<usize, String> {
    statement
        .execute(params![name])
        .map_err(|error| format!("database operation failed: {error}"))
}
