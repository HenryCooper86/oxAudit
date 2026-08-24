use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use tauri::Manager;
use tempfile::NamedTempFile;

use crate::credentials::{CredentialKind, CredentialStore};
use crate::findings::error::CommandError;
use crate::models::{
    AppSettings, CredentialMutation, CredentialPresence, SaveSettingsRequest, SaveSettingsResult,
};

/// Path to the settings file inside the app config directory.
pub fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot resolve config dir: {e}"))?;
    Ok(dir.join("settings.json"))
}

pub fn load(
    app: &tauri::AppHandle,
    credentials: &dyn CredentialStore,
) -> Result<AppSettings, CommandError> {
    let path = settings_path(app).map_err(|_| CommandError::persistence_unavailable())?;
    load_secure_from_path(&path, credentials)
}

pub fn save(
    app: &tauri::AppHandle,
    credentials: &dyn CredentialStore,
    request: SaveSettingsRequest,
) -> Result<SaveSettingsResult, CommandError> {
    let path = settings_path(app).map_err(|_| CommandError::persistence_unavailable())?;
    save_secure_to_path(&path, credentials, request)
}

pub(crate) fn load_secure_from_path(
    path: &Path,
    credentials: &dyn CredentialStore,
) -> Result<AppSettings, CommandError> {
    let (raw, existed) = match fs::read_to_string(path) {
        Ok(content) => (
            serde_json::from_str::<serde_json::Value>(&content)
                .map_err(|_| CommandError::migration_failed())?,
            true,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (serde_json::json!({}), false)
        }
        Err(_) => return Err(CommandError::persistence_unavailable()),
    };

    let legacy_ai = raw
        .pointer("/ai/apiKey")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let legacy_nvd = raw
        .get("nvdApiKey")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let contained_legacy_fields =
        raw.pointer("/ai/apiKey").is_some() || raw.get("nvdApiKey").is_some();

    let mut settings: AppSettings =
        serde_json::from_value(raw).map_err(|_| CommandError::migration_failed())?;

    migrate_legacy_credential(
        credentials,
        CredentialKind::AiProvider,
        legacy_ai.as_deref(),
    )?;
    migrate_legacy_credential(credentials, CredentialKind::Nvd, legacy_nvd.as_deref())?;

    let presence = credential_presence(credentials)?;
    let presence_changed = settings.credentials != presence;
    settings.credentials = presence;

    if existed && (contained_legacy_fields || presence_changed) {
        save_to_path(path, &settings).map_err(|_| CommandError::persistence_unavailable())?;
    }
    Ok(settings)
}

fn migrate_legacy_credential(
    credentials: &dyn CredentialStore,
    kind: CredentialKind,
    legacy: Option<&str>,
) -> Result<(), CommandError> {
    if let Some(value) = legacy {
        if credentials.get(kind)?.is_none() {
            credentials.set(kind, value)?;
        }
    }
    Ok(())
}

fn credential_presence(
    credentials: &dyn CredentialStore,
) -> Result<CredentialPresence, CommandError> {
    Ok(CredentialPresence {
        ai_api_key: credentials.get(CredentialKind::AiProvider)?.is_some(),
        nvd_api_key: credentials.get(CredentialKind::Nvd)?.is_some(),
    })
}

fn apply_mutation(
    credentials: &dyn CredentialStore,
    kind: CredentialKind,
    mutation: &CredentialMutation,
) -> Result<(), CommandError> {
    match mutation {
        CredentialMutation::Unchanged => Ok(()),
        CredentialMutation::Replace { value } => {
            let value = value.trim();
            if value.is_empty() || value.len() > 16 * 1024 {
                return Err(CommandError::credential_unavailable());
            }
            credentials.set(kind, value)
        }
        CredentialMutation::Delete => credentials.delete(kind),
    }
}

fn restore_credential(
    credentials: &dyn CredentialStore,
    kind: CredentialKind,
    previous: Option<&str>,
) -> Result<(), CommandError> {
    match previous {
        Some(value) => credentials.set(kind, value),
        None => credentials.delete(kind),
    }
}

fn rollback_credentials(
    credentials: &dyn CredentialStore,
    previous_ai: Option<&str>,
    previous_nvd: Option<&str>,
) -> Result<(), CommandError> {
    let ai = restore_credential(credentials, CredentialKind::AiProvider, previous_ai);
    let nvd = restore_credential(credentials, CredentialKind::Nvd, previous_nvd);
    if ai.is_err() || nvd.is_err() {
        return Err(CommandError::credential_rollback_failed());
    }
    Ok(())
}

fn save_secure_to_path(
    path: &Path,
    credentials: &dyn CredentialStore,
    request: SaveSettingsRequest,
) -> Result<SaveSettingsResult, CommandError> {
    let previous_ai = credentials.get(CredentialKind::AiProvider)?;
    let previous_nvd = credentials.get(CredentialKind::Nvd)?;

    let mutation_result =
        apply_mutation(credentials, CredentialKind::AiProvider, &request.ai_api_key)
            .and_then(|()| apply_mutation(credentials, CredentialKind::Nvd, &request.nvd_api_key));
    if let Err(error) = mutation_result {
        rollback_credentials(
            credentials,
            previous_ai.as_deref().map(String::as_str),
            previous_nvd.as_deref().map(String::as_str),
        )?;
        return Err(error);
    }

    let mut settings = request.settings;
    settings.credentials = match credential_presence(credentials) {
        Ok(presence) => presence,
        Err(error) => {
            rollback_credentials(
                credentials,
                previous_ai.as_deref().map(String::as_str),
                previous_nvd.as_deref().map(String::as_str),
            )?;
            return Err(error);
        }
    };

    if save_to_path(path, &settings).is_err() {
        rollback_credentials(
            credentials,
            previous_ai.as_deref().map(String::as_str),
            previous_nvd.as_deref().map(String::as_str),
        )?;
        return Err(CommandError::persistence_unavailable());
    }

    Ok(SaveSettingsResult { settings })
}

/// Persist settings as one atomic replacement in the destination directory.
///
/// Although credentials live in the OS store, Unix builds also make the
/// settings directory owner-only and every newly committed file mode 0600.
/// A failed serialization, write, or sync leaves the previous file untouched.
pub(crate) fn save_to_path(path: &Path, settings: &AppSettings) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create config dir: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("cannot protect config dir: {error}"))?;
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| "settings path has no parent directory".to_string())?;
    let content = serde_json::to_vec_pretty(settings)
        .map_err(|error| format!("cannot serialize settings: {error}"))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create temporary settings file: {error}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot protect temporary settings file: {error}"))?;
    }

    temporary
        .write_all(&content)
        .map_err(|error| format!("cannot write temporary settings file: {error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("cannot sync temporary settings file: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("cannot replace settings file: {}", error.error))?;

    // Best-effort directory synchronization makes the rename durable on Unix.
    // The settings file is already committed at this point, so a platform that
    // cannot sync directories must not turn a successful save into a false
    // failure that prompts the caller to overwrite it again.
    #[cfg(unix)]
    let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{load_secure_from_path, save_secure_to_path, save_to_path};
    use crate::credentials::{CredentialKind, CredentialStore, MemoryCredentialStore};
    use crate::models::{AppSettings, CredentialMutation, CredentialPresence, SaveSettingsRequest};
    use std::fs;

    #[test]
    fn a_missing_settings_file_loads_defaults() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = MemoryCredentialStore::default();
        let loaded = load_secure_from_path(&directory.path().join("settings.json"), &store)
            .expect("defaults");

        assert_eq!(loaded.theme, "dark");
        assert_eq!(loaded.ai.model, "gpt-4o-mini");
        assert!(loaded.scan.scan_secrets);
    }

    #[test]
    fn malformed_settings_are_reported_instead_of_silently_reset() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("settings.json");
        fs::write(&path, b"{ definitely-not-json").expect("fixture");

        let store = MemoryCredentialStore::default();
        let error =
            load_secure_from_path(&path, &store).expect_err("invalid settings must be visible");
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::MigrationFailed
        );
        assert!(!error.message.contains("definitely-not-json"));
    }

    #[test]
    fn partial_legacy_settings_receive_current_defaults() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("settings.json");
        fs::write(&path, br#"{"theme":"light"}"#).expect("fixture");

        let store = MemoryCredentialStore::default();
        let loaded = load_secure_from_path(&path, &store).expect("legacy settings");
        assert_eq!(loaded.theme, "light");
        assert_eq!(loaded.ai.context_window, 128_000);
        assert!(loaded.scan.scan_vulnerabilities);
    }

    #[test]
    fn saving_atomically_replaces_the_complete_snapshot() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("nested/settings.json");
        let first = AppSettings {
            theme: "light".into(),
            ..AppSettings::default()
        };
        save_to_path(&path, &first).expect("first save");

        let second = AppSettings {
            credentials: CredentialPresence {
                ai_api_key: true,
                nvd_api_key: false,
            },
            ..AppSettings::default()
        };
        save_to_path(&path, &second).expect("replacement save");

        let store = MemoryCredentialStore::default();
        let loaded = load_secure_from_path(&path, &store).expect("saved settings");
        assert_eq!(loaded.theme, "dark");
        assert!(!loaded.credentials.ai_api_key);
        assert_eq!(
            fs::read_dir(path.parent().expect("parent"))
                .expect("directory")
                .count(),
            1,
            "the atomic save must not leave temporary files behind"
        );
    }

    #[test]
    fn plaintext_legacy_credentials_move_to_protected_storage_and_are_scrubbed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("settings.json");
        fs::write(
            &path,
            br#"{"ai":{"apiKey":"ai-canary"},"nvdApiKey":"nvd-canary"}"#,
        )
        .expect("fixture");
        let store = MemoryCredentialStore::default();

        let loaded = load_secure_from_path(&path, &store).expect("migration");

        assert!(loaded.credentials.ai_api_key);
        assert!(loaded.credentials.nvd_api_key);
        assert_eq!(
            store
                .get(CredentialKind::AiProvider)
                .expect("AI key")
                .as_deref()
                .map(String::as_str),
            Some("ai-canary")
        );
        let persisted = fs::read_to_string(path).expect("sanitized settings");
        assert!(!persisted.contains("ai-canary"));
        assert!(!persisted.contains("nvd-canary"));
        let persisted: serde_json::Value =
            serde_json::from_str(&persisted).expect("sanitized JSON");
        assert!(persisted.pointer("/ai/apiKey").is_none());
        assert!(persisted.get("nvdApiKey").is_none());
    }

    #[test]
    fn secure_save_applies_explicit_mutations_and_serializes_presence_only() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("settings.json");
        let store = MemoryCredentialStore::default();
        store.set(CredentialKind::Nvd, "old-nvd").expect("seed");

        let result = save_secure_to_path(
            &path,
            &store,
            SaveSettingsRequest {
                settings: AppSettings::default(),
                ai_api_key: CredentialMutation::Replace {
                    value: "new-ai-canary".into(),
                },
                nvd_api_key: CredentialMutation::Delete,
            },
        )
        .expect("secure save");

        assert!(result.settings.credentials.ai_api_key);
        assert!(!result.settings.credentials.nvd_api_key);
        let persisted = fs::read_to_string(path).expect("settings");
        assert!(!persisted.contains("new-ai-canary"));
        assert!(!persisted.contains("old-nvd"));
    }

    #[test]
    fn a_settings_write_failure_restores_previous_credentials() {
        let directory = tempfile::tempdir().expect("tempdir");
        let destination_is_directory = directory.path().join("settings.json");
        fs::create_dir(&destination_is_directory).expect("blocking destination");
        let store = MemoryCredentialStore::default();
        store
            .set(CredentialKind::AiProvider, "previous-ai")
            .expect("seed");

        let error = save_secure_to_path(
            &destination_is_directory,
            &store,
            SaveSettingsRequest {
                settings: AppSettings::default(),
                ai_api_key: CredentialMutation::Replace {
                    value: "replacement-ai".into(),
                },
                nvd_api_key: CredentialMutation::Replace {
                    value: "replacement-nvd".into(),
                },
            },
        )
        .expect_err("write must fail");

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PersistenceUnavailable
        );
        assert_eq!(
            store
                .get(CredentialKind::AiProvider)
                .expect("AI")
                .as_deref()
                .map(String::as_str),
            Some("previous-ai")
        );
        assert!(store.get(CredentialKind::Nvd).expect("NVD").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn saved_credentials_are_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private/settings.json");
        save_to_path(&path, &AppSettings::default()).expect("save");

        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().expect("parent"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
