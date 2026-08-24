use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Manager;
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::credentials::CredentialStore;
use crate::findings::error::CommandError;

const LEGACY_IDENTIFIER: &str = "com.vulncompanion.app";
const CURRENT_IDENTIFIER: &str = "com.oxaudit.desktop";
const CHECKPOINT_FILE: &str = "identity-migration-v1.json";
const MAX_ENTRIES: u64 = 100_000;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    NotNeeded,
    Completed,
    AlreadyCompleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum MigrationPhase {
    Copying,
    SanitizingCredentials,
    Completed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationCheckpoint {
    schema_version: u8,
    legacy_identifier: String,
    current_identifier: String,
    phase: MigrationPhase,
}

impl MigrationCheckpoint {
    fn new(phase: MigrationPhase) -> Self {
        Self {
            schema_version: 1,
            legacy_identifier: LEGACY_IDENTIFIER.to_owned(),
            current_identifier: CURRENT_IDENTIFIER.to_owned(),
            phase,
        }
    }

    fn is_valid(&self) -> bool {
        self.schema_version == 1
            && self.legacy_identifier == LEGACY_IDENTIFIER
            && self.current_identifier == CURRENT_IDENTIFIER
    }
}

pub fn migrate_legacy_profile(
    app: &tauri::AppHandle,
    credentials: &dyn CredentialStore,
) -> Result<MigrationOutcome, CommandError> {
    let new_config = app
        .path()
        .app_config_dir()
        .map_err(|_| CommandError::migration_failed())?;
    let new_data = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::migration_failed())?;
    let old_config = legacy_sibling(&new_config)?;
    let old_data = legacy_sibling(&new_data)?;

    migrate_paths(&old_config, &new_config, &old_data, &new_data, credentials)
}

fn legacy_sibling(current: &Path) -> Result<PathBuf, CommandError> {
    if current.file_name().and_then(|name| name.to_str()) != Some(CURRENT_IDENTIFIER) {
        return Err(CommandError::migration_failed());
    }
    let parent = current
        .parent()
        .ok_or_else(CommandError::migration_failed)?;
    Ok(parent.join(LEGACY_IDENTIFIER))
}

fn migrate_paths(
    old_config: &Path,
    new_config: &Path,
    old_data: &Path,
    new_data: &Path,
    credentials: &dyn CredentialStore,
) -> Result<MigrationOutcome, CommandError> {
    let old_config_exists = safe_directory_exists(old_config)?;
    let old_data_exists = if old_data == old_config {
        old_config_exists
    } else {
        safe_directory_exists(old_data)?
    };
    if !old_config_exists && !old_data_exists {
        return Ok(MigrationOutcome::NotNeeded);
    }

    ensure_directory(new_config)?;
    let checkpoint_path = new_config.join(CHECKPOINT_FILE);
    if let Some(checkpoint) = read_checkpoint(&checkpoint_path)? {
        if !checkpoint.is_valid() {
            return Err(CommandError::migration_failed());
        }
        if checkpoint.phase == MigrationPhase::Completed {
            return Ok(MigrationOutcome::AlreadyCompleted);
        }
    }

    write_checkpoint(&checkpoint_path, MigrationPhase::Copying)?;
    let mut budget = CopyBudget::default();
    if old_config_exists {
        copy_tree(old_config, new_config, &mut budget, true)?;
    }
    if old_data_exists && (old_data != old_config || new_data != new_config) {
        copy_tree(old_data, new_data, &mut budget, false)?;
    }

    write_checkpoint(&checkpoint_path, MigrationPhase::SanitizingCredentials)?;
    let new_settings = new_config.join("settings.json");
    if safe_regular_file_exists(&new_settings)? {
        crate::settings::load_secure_from_path(&new_settings, credentials)?;
    }
    let old_settings = old_config.join("settings.json");
    if old_settings != new_settings && safe_regular_file_exists(&old_settings)? {
        // The legacy profile is retained as a recoverable backup, but it must
        // not retain plaintext credentials after the new profile is live.
        crate::settings::load_secure_from_path(&old_settings, credentials)?;
    }

    write_checkpoint(&checkpoint_path, MigrationPhase::Completed)?;
    Ok(MigrationOutcome::Completed)
}

#[derive(Default)]
struct CopyBudget {
    entries: u64,
    bytes: u64,
}

impl CopyBudget {
    fn account(&mut self, bytes: u64) -> Result<(), CommandError> {
        self.entries = self.entries.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.entries > MAX_ENTRIES || self.bytes > MAX_BYTES {
            return Err(CommandError::migration_failed());
        }
        Ok(())
    }
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    budget: &mut CopyBudget,
    skip_checkpoint: bool,
) -> Result<(), CommandError> {
    ensure_directory(destination)?;
    for entry in WalkDir::new(source).follow_links(false).min_depth(1) {
        let entry = entry.map_err(|_| CommandError::migration_failed())?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|_| CommandError::migration_failed())?;
        if skip_checkpoint && relative == Path::new(CHECKPOINT_FILE) {
            continue;
        }

        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| CommandError::migration_failed())?;
        if metadata.file_type().is_symlink() {
            return Err(CommandError::migration_failed());
        }
        let target = destination.join(relative);
        if metadata.is_dir() {
            budget.account(0)?;
            ensure_directory(&target)?;
        } else if metadata.is_file() {
            budget.account(metadata.len())?;
            copy_regular_file(entry.path(), &target)?;
        } else {
            return Err(CommandError::migration_failed());
        }
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), CommandError> {
    if let Some(parent) = destination.parent() {
        ensure_directory(parent)?;
    }
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(CommandError::migration_failed());
            }
            if !same_file_contents(source, destination)? {
                return Err(CommandError::migration_failed());
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(CommandError::migration_failed()),
    }

    let parent = destination
        .parent()
        .ok_or_else(CommandError::migration_failed)?;
    let mut input = open_read_no_follow(source)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| CommandError::migration_failed())?;
    std::io::copy(&mut input, temporary.as_file_mut())
        .map_err(|_| CommandError::migration_failed())?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| CommandError::migration_failed())?;
    protect_file(temporary.path())?;
    match temporary.persist_noclobber(destination) {
        Ok(_) => {}
        Err(_) if same_file_contents(source, destination).unwrap_or(false) => return Ok(()),
        Err(_) => return Err(CommandError::migration_failed()),
    }
    sync_directory(parent)?;
    Ok(())
}

fn same_file_contents(left: &Path, right: &Path) -> Result<bool, CommandError> {
    let left_metadata = fs::symlink_metadata(left).map_err(|_| CommandError::migration_failed())?;
    let right_metadata =
        fs::symlink_metadata(right).map_err(|_| CommandError::migration_failed())?;
    if !left_metadata.is_file()
        || !right_metadata.is_file()
        || left_metadata.file_type().is_symlink()
        || right_metadata.file_type().is_symlink()
        || left_metadata.len() != right_metadata.len()
    {
        return Ok(false);
    }
    Ok(file_digest(left)? == file_digest(right)?)
}

fn file_digest(path: &Path) -> Result<[u8; 32], CommandError> {
    let mut file = open_read_no_follow(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| CommandError::migration_failed())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

fn open_read_no_follow(path: &Path) -> Result<File, CommandError> {
    let mut options = OpenOptions::new();
    options.read(true);
    add_no_follow_flag(&mut options);
    options
        .open(path)
        .map_err(|_| CommandError::migration_failed())
}

fn add_no_follow_flag(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

fn safe_directory_exists(path: &Path) -> Result<bool, CommandError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(CommandError::migration_failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CommandError::migration_failed()),
    }
}

fn safe_regular_file_exists(path: &Path) -> Result<bool, CommandError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(CommandError::migration_failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CommandError::migration_failed()),
    }
}

fn ensure_directory(path: &Path) -> Result<(), CommandError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(CommandError::migration_failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| CommandError::migration_failed())?;
        }
        Err(_) => return Err(CommandError::migration_failed()),
    }
    protect_directory(path)
}

fn protect_directory(path: &Path) -> Result<(), CommandError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| CommandError::migration_failed())?;
    }
    Ok(())
}

fn protect_file(path: &Path) -> Result<(), CommandError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| CommandError::migration_failed())?;
    }
    Ok(())
}

fn read_checkpoint(path: &Path) -> Result<Option<MigrationCheckpoint>, CommandError> {
    if !safe_regular_file_exists(path)? {
        return Ok(None);
    }
    let file = open_read_no_follow(path)?;
    let mut content = Vec::new();
    file.take(16 * 1024)
        .read_to_end(&mut content)
        .map_err(|_| CommandError::migration_failed())?;
    serde_json::from_slice(&content)
        .map(Some)
        .map_err(|_| CommandError::migration_failed())
}

fn write_checkpoint(path: &Path, phase: MigrationPhase) -> Result<(), CommandError> {
    let parent = path.parent().ok_or_else(CommandError::migration_failed)?;
    ensure_directory(parent)?;
    let content = serde_json::to_vec_pretty(&MigrationCheckpoint::new(phase))
        .map_err(|_| CommandError::migration_failed())?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| CommandError::migration_failed())?;
    temporary
        .as_file()
        .set_len(0)
        .map_err(|_| CommandError::migration_failed())?;
    temporary
        .write_all(&content)
        .map_err(|_| CommandError::migration_failed())?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| CommandError::migration_failed())?;
    protect_file(temporary.path())?;
    temporary
        .persist(path)
        .map_err(|_| CommandError::migration_failed())?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), CommandError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CommandError::migration_failed())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), CommandError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialKind, MemoryCredentialStore};

    fn roots() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("tempdir");
        let config = root.path().join("config");
        let data = root.path().join("data");
        (
            root,
            config.join(LEGACY_IDENTIFIER),
            config.join(CURRENT_IDENTIFIER),
            data.join(LEGACY_IDENTIFIER),
            data.join(CURRENT_IDENTIFIER),
        )
    }

    #[test]
    fn absent_legacy_profile_does_not_create_a_new_profile() {
        let (_root, old_config, new_config, old_data, new_data) = roots();
        let result = migrate_paths(
            &old_config,
            &new_config,
            &old_data,
            &new_data,
            &MemoryCredentialStore::default(),
        )
        .expect("not needed");
        assert_eq!(result, MigrationOutcome::NotNeeded);
        assert!(!new_config.exists());
        assert!(!new_data.exists());
    }

    #[test]
    fn migration_copies_both_roots_scrubs_backups_and_is_idempotent() {
        let (_root, old_config, new_config, old_data, new_data) = roots();
        fs::create_dir_all(old_config.join("sessions")).expect("legacy config");
        fs::create_dir_all(old_data.join("findings")).expect("legacy data");
        fs::write(
            old_config.join("settings.json"),
            br#"{"ai":{"apiKey":"ai-canary"},"nvdApiKey":"nvd-canary"}"#,
        )
        .expect("legacy settings");
        fs::write(old_config.join("sessions/one.jsonl"), b"session\n").expect("session");
        fs::write(old_data.join("findings/findings.sqlite3"), b"database").expect("database");
        let store = MemoryCredentialStore::default();

        let first = migrate_paths(&old_config, &new_config, &old_data, &new_data, &store)
            .expect("migration");
        let second = migrate_paths(&old_config, &new_config, &old_data, &new_data, &store)
            .expect("idempotent migration");

        assert_eq!(first, MigrationOutcome::Completed);
        assert_eq!(second, MigrationOutcome::AlreadyCompleted);
        assert_eq!(
            fs::read(new_config.join("sessions/one.jsonl")).unwrap(),
            b"session\n"
        );
        assert_eq!(
            fs::read(new_data.join("findings/findings.sqlite3")).unwrap(),
            b"database"
        );
        assert_eq!(
            store
                .get(CredentialKind::AiProvider)
                .expect("credential")
                .as_deref()
                .map(String::as_str),
            Some("ai-canary")
        );
        for settings in [
            old_config.join("settings.json"),
            new_config.join("settings.json"),
        ] {
            let content = fs::read_to_string(settings).expect("sanitized settings");
            assert!(!content.contains("ai-canary"));
            assert!(!content.contains("nvd-canary"));
        }
        let checkpoint: MigrationCheckpoint = serde_json::from_slice(
            &fs::read(new_config.join(CHECKPOINT_FILE)).expect("checkpoint"),
        )
        .expect("checkpoint JSON");
        assert_eq!(checkpoint.phase, MigrationPhase::Completed);
    }

    #[test]
    fn an_interrupted_copy_restarts_without_overwriting_matching_files() {
        let (_root, old_config, new_config, old_data, new_data) = roots();
        fs::create_dir_all(&old_config).expect("legacy config");
        fs::create_dir_all(&new_config).expect("new config");
        fs::write(old_config.join("sessions.jsonl"), b"same").expect("legacy file");
        fs::write(new_config.join("sessions.jsonl"), b"same").expect("partial copy");
        write_checkpoint(&new_config.join(CHECKPOINT_FILE), MigrationPhase::Copying)
            .expect("interrupted checkpoint");

        let result = migrate_paths(
            &old_config,
            &new_config,
            &old_data,
            &new_data,
            &MemoryCredentialStore::default(),
        )
        .expect("resume");
        assert_eq!(result, MigrationOutcome::Completed);
    }

    #[test]
    fn a_destination_conflict_fails_closed_without_overwriting_either_file() {
        let (_root, old_config, new_config, old_data, new_data) = roots();
        fs::create_dir_all(&old_config).expect("legacy config");
        fs::create_dir_all(&new_config).expect("new config");
        fs::write(old_config.join("sessions.jsonl"), b"legacy").expect("legacy file");
        fs::write(new_config.join("sessions.jsonl"), b"current").expect("current file");

        let result = migrate_paths(
            &old_config,
            &new_config,
            &old_data,
            &new_data,
            &MemoryCredentialStore::default(),
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(old_config.join("sessions.jsonl")).unwrap(),
            b"legacy"
        );
        assert_eq!(
            fs::read(new_config.join("sessions.jsonl")).unwrap(),
            b"current"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_symlinks_are_rejected_instead_of_followed() {
        use std::os::unix::fs::symlink;

        let (root, old_config, new_config, old_data, new_data) = roots();
        fs::create_dir_all(&old_config).expect("legacy config");
        let outside = root.path().join("outside");
        fs::write(&outside, b"secret").expect("outside file");
        symlink(&outside, old_config.join("linked")).expect("symlink");

        let result = migrate_paths(
            &old_config,
            &new_config,
            &old_data,
            &new_data,
            &MemoryCredentialStore::default(),
        );
        assert!(result.is_err());
        assert!(!new_config.join("linked").is_file());
    }
}
