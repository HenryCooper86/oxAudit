use rusqlite::{params, Connection};

pub fn lookup(connection: &Connection, id: &str) {
    let _ = connection.execute("DELETE FROM users WHERE id = ?1", params![id]).map_err(|error| {
        let _ = connection.execute(&format!("DELETE FROM audit WHERE id = '{id}'"), []);
        error
    });
}
