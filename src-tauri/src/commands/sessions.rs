//! Assistant session storage commands.
//!
//! Split out of `commands/mod.rs`, which had grown to 3,279 production lines
//! across 61 commands. A child module rather than a sibling file, so
//! `use super::*` still reaches the shared state and helpers without widening
//! anything to `pub`.

use super::*;

#[tauri::command]
pub fn session_list(app: AppHandle) -> Result<Vec<crate::sessions::SessionInfo>, String> {
    crate::sessions::SessionStore::new(&app)?.list()
}

#[tauri::command]
pub fn session_create(
    app: AppHandle,
    title: Option<String>,
    project_path: Option<String>,
) -> Result<crate::sessions::SessionInfo, String> {
    crate::sessions::SessionStore::new(&app)?.create(title, project_path)
}

#[tauri::command]
pub fn session_get_messages(
    app: AppHandle,
    session_id: String,
) -> Result<Vec<crate::sessions::StoredMessage>, String> {
    crate::sessions::SessionStore::new(&app)?.get_messages(&session_id)
}

#[tauri::command]
pub fn session_append(
    app: AppHandle,
    session_id: String,
    message: crate::sessions::StoredMessage,
) -> Result<crate::sessions::SessionInfo, String> {
    crate::sessions::SessionStore::new(&app)?.append(&session_id, &message)
}

#[tauri::command]
pub fn session_rename(app: AppHandle, session_id: String, title: String) -> Result<(), String> {
    crate::sessions::SessionStore::new(&app)?.rename(&session_id, title)
}

#[tauri::command]
pub fn session_delete(app: AppHandle, session_id: String) -> Result<(), String> {
    crate::sessions::SessionStore::new(&app)?.delete(&session_id)
}

#[tauri::command]
pub fn session_truncate(
    app: AppHandle,
    session_id: String,
    keep_count: usize,
) -> Result<(), String> {
    crate::sessions::SessionStore::new(&app)?.truncate(&session_id, keep_count)
}
