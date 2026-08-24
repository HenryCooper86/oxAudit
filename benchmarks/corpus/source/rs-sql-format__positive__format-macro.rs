use rusqlite::Connection;

pub fn lookup(connection: &Connection, user_id: &str) -> rusqlite::Result<usize> {
    connection.execute(&format!("SELECT * FROM users WHERE id = {user_id}"), [])
}
