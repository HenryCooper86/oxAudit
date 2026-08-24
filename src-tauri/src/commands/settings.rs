//! Settings, active project, and diagnostics commands.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;

/// Set or explicitly clear the project folder the agent's file tools operate on.
#[tauri::command]
pub fn set_active_project(state: State<'_, AppState>, path: Option<String>) -> Result<(), String> {
    let project = active_project_path(path)?;
    *state.active_project.lock().unwrap() = project;
    Ok(())
}

#[tauri::command]
pub fn load_settings(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSettings, CommandError> {
    let settings = crate::settings::load(&app, state.credentials.as_ref())?;
    *state.settings.lock().unwrap() = settings.clone();
    Ok(settings)
}

#[tauri::command]
pub fn save_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    request: SaveSettingsRequest,
) -> Result<SaveSettingsResult, CommandError> {
    let mut current = state.settings.lock().unwrap();
    let result = crate::settings::save(&app, state.credentials.as_ref(), request)?;
    *current = result.settings.clone();
    Ok(result)
}

/// Everything a person needs in order to report a problem, redacted.
///
/// Returned to the GUI rather than written to a file: the user copies it and
/// decides who sees it. oxAudit sends nothing anywhere.
#[tauri::command]
pub fn collect_diagnostics(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<crate::observability::Diagnostics, String> {
    // Whether an endpoint is configured, never which one — a base URL is
    // sometimes an internal host, and that is itself worth not disclosing.
    let ai_configured = state
        .settings
        .lock()
        .map(|settings| settings.ai.enabled && !settings.ai.base_url.trim().is_empty())
        .unwrap_or(false);
    let home = app.path().home_dir().ok();
    Ok(crate::observability::collect(
        ai_configured,
        home.as_deref(),
    ))
}
