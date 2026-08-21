mod agent;
mod ai;
pub mod binscan;
mod commands;
pub mod cve;
mod deps;
pub mod exploit;
pub mod findings;
mod fs_utils;
mod models;
mod scanners;
mod sessions;
mod settings;
pub mod triage;

use tauri::Manager;

use commands::AppState;
use findings::{
    repository::FindingsRepository,
    service::{FindingsService, FindingsState},
};

pub(crate) fn initialize_findings_state(
    app_data_root: &std::path::Path,
    recovered_at: chrono::DateTime<chrono::Utc>,
) -> FindingsState {
    let initialized = (|| {
        match std::fs::symlink_metadata(app_data_root.join("findings.sqlite3")) {
            Ok(_) => return Err(findings::error::CommandError::persistence_unavailable()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(findings::error::CommandError::persistence_unavailable()),
        }
        let database_path = findings::database_path(app_data_root);
        let repository = FindingsRepository::open(database_path)?;
        repository.recover_interrupted_runs(recovered_at)?;
        Ok::<_, findings::error::CommandError>(FindingsService::new(repository))
    })();
    match initialized {
        Ok(service) => FindingsState::available(service),
        Err(error) => FindingsState::unavailable(error),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::new();
    let cve_state = cve::CveState::new(state.http.clone());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .manage(cve_state)
        .setup(|app| {
            let findings_state = match app.path().app_data_dir() {
                Ok(data_dir) => initialize_findings_state(&data_dir, chrono::Utc::now()),
                Err(_) => FindingsState::unavailable(
                    findings::error::CommandError::persistence_unavailable(),
                ),
            };
            app.manage(findings_state);
            // Load persisted settings, apply NVD key
            let settings = settings::load(app.handle());
            if let Some(app_state) = app.try_state::<AppState>() {
                *app_state.settings.lock().unwrap() = settings.clone();
            }
            if let Some(cve) = app.try_state::<cve::CveState>() {
                if let Ok(mut key) = cve.api_key.lock() {
                    *key = settings.nvd_api_key.clone();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan_project,
            commands::cancel_scan,
            commands::open_scan_finding,
            commands::inspect_source_project,
            commands::list_source_projects,
            commands::list_source_runs,
            commands::load_source_run,
            commands::retry_source_run_save,
            commands::save_finding_review,
            commands::delete_finding_review,
            commands::scan_dependencies,
            commands::find_lockfiles,
            commands::search_cves,
            commands::cve_detail,
            commands::osv_package_vulns,
            commands::chat,
            commands::stream_chat,
            commands::cancel_chat,
            commands::steer_chat,
            commands::todo_list,
            commands::binary_tool_status,
            commands::scan_binaries,
            commands::cancel_binary_scan,
            commands::refresh_binary_database,
            commands::respond_permission,
            commands::respond_interaction,
            commands::set_active_project,
            commands::analyze_finding,
            commands::research_cve,
            commands::test_ai,
            commands::test_ai_with,
            commands::get_conversation_usage,
            commands::get_total_usage,
            commands::session_list,
            commands::session_create,
            commands::session_get_messages,
            commands::session_append,
            commands::session_rename,
            commands::session_delete,
            commands::session_truncate,
            commands::load_settings,
            commands::save_settings,
            commands::get_ai_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    fn set_mode(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::symlink_metadata(path)
            .expect("read permissions")
            .permissions();
        permissions.set_mode(mode);
        std::fs::set_permissions(path, permissions).expect("set permissions");
    }

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::symlink_metadata(path)
            .expect("read permissions")
            .permissions()
            .mode()
            & 0o777
    }

    fn initialization_error(
        state: &crate::findings::service::FindingsState,
    ) -> crate::findings::error::CommandError {
        match state.service() {
            Ok(_) => panic!("findings initialization unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn findings_startup_rejects_unsupported_interim_root_database_without_mutation() {
        let app_data = tempfile::tempdir().expect("shared app-data root");
        let interim_database = app_data.path().join("findings.sqlite3");
        let interim_bytes = b"unreleased-interim-database";
        std::fs::write(&interim_database, interim_bytes).expect("interim database fixture");

        let state = crate::initialize_findings_state(app_data.path(), chrono::Utc::now());

        let error = initialization_error(&state);
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PersistenceUnavailable
        );
        assert_eq!(std::fs::read(&interim_database).unwrap(), interim_bytes);
        assert!(!app_data.path().join("findings").exists());
    }

    #[test]
    fn findings_startup_rejects_ambiguous_root_and_nested_databases() {
        let app_data = tempfile::tempdir().expect("shared app-data root");
        let nested_database = crate::findings::database_path(app_data.path());
        let repository = crate::findings::repository::FindingsRepository::open(&nested_database)
            .expect("nested database fixture");
        drop(repository);
        let nested_bytes = std::fs::read(&nested_database).expect("nested database bytes");
        let interim_database = app_data.path().join("findings.sqlite3");
        let interim_bytes = b"ambiguous-interim-database";
        std::fs::write(&interim_database, interim_bytes).expect("interim database fixture");

        let state = crate::initialize_findings_state(app_data.path(), chrono::Utc::now());

        let error = initialization_error(&state);
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PersistenceUnavailable
        );
        assert_eq!(std::fs::read(&interim_database).unwrap(), interim_bytes);
        assert_eq!(std::fs::read(&nested_database).unwrap(), nested_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn findings_startup_uses_private_child_without_mutating_shared_app_data() {
        let app_data = tempfile::tempdir().expect("shared app-data root");
        let settings = app_data.path().join("settings.json");
        let sessions = app_data.path().join("sessions");
        let session = sessions.join("session.jsonl");
        std::fs::create_dir(&sessions).expect("sessions directory");
        std::fs::write(&settings, br#"{"theme":"dark"}"#).expect("settings fixture");
        std::fs::write(&session, b"retained session\n").expect("session fixture");
        set_mode(app_data.path(), 0o755);
        set_mode(&settings, 0o644);
        set_mode(&sessions, 0o755);
        set_mode(&session, 0o644);
        let settings_bytes = std::fs::read(&settings).unwrap();
        let session_bytes = std::fs::read(&session).unwrap();

        let state = crate::initialize_findings_state(app_data.path(), chrono::Utc::now());

        assert!(state.service().is_ok());
        assert_eq!(mode(app_data.path()), 0o755);
        assert_eq!(mode(&settings), 0o644);
        assert_eq!(mode(&sessions), 0o755);
        assert_eq!(mode(&session), 0o644);
        assert_eq!(std::fs::read(&settings).unwrap(), settings_bytes);
        assert_eq!(std::fs::read(&session).unwrap(), session_bytes);
        assert_eq!(mode(&app_data.path().join("findings")), 0o700);
        assert_eq!(
            mode(&crate::findings::database_path(app_data.path())),
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn findings_startup_rejects_unsafe_preexisting_private_child() {
        let app_data = tempfile::tempdir().expect("shared app-data root");
        let findings = app_data.path().join("findings");
        std::fs::create_dir(&findings).expect("findings directory");
        std::fs::write(app_data.path().join("settings.json"), b"preserve")
            .expect("settings fixture");
        set_mode(app_data.path(), 0o755);
        set_mode(&findings, 0o755);

        let state = crate::initialize_findings_state(app_data.path(), chrono::Utc::now());

        let error = initialization_error(&state);
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PersistenceUnavailable
        );
        assert_eq!(mode(app_data.path()), 0o755);
        assert_eq!(mode(&findings), 0o755);
        assert_eq!(
            std::fs::read(app_data.path().join("settings.json")).unwrap(),
            b"preserve"
        );
        assert!(!findings.join("findings.sqlite3").exists());
    }

    #[cfg(unix)]
    #[test]
    fn findings_startup_rejects_symlinked_private_child_without_writing_target() {
        use std::os::unix::fs::symlink;

        let app_data = tempfile::tempdir().expect("shared app-data root");
        let redirected = tempfile::tempdir().expect("redirect target");
        set_mode(app_data.path(), 0o755);
        set_mode(redirected.path(), 0o700);
        symlink(redirected.path(), app_data.path().join("findings"))
            .expect("symlink findings directory");

        let state = crate::initialize_findings_state(app_data.path(), chrono::Utc::now());

        let error = initialization_error(&state);
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PersistenceUnavailable
        );
        assert!(!redirected.path().join("findings.sqlite3").exists());
        assert!(std::fs::symlink_metadata(app_data.path().join("findings"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    fn source_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("fixture tempdir");
        let files = [
            (
                "app.js",
                "eval(userInput);\nconst token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';\n",
            ),
            ("shell.js", "exec('ls ' + userInput);\n"),
            (
                "query.js",
                "db.query('SELECT * FROM users WHERE id=' + id);\n",
            ),
            (
                "worker.py",
                "eval(payload)\npickle.loads(blob)\nos.system(command)\n",
            ),
            (
                "query.py",
                "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n",
            ),
        ];
        for (name, content) in files {
            std::fs::write(dir.path().join(name), content).expect("write source fixture");
        }
        dir
    }

    #[test]
    fn fixture_scan_finds_secrets_and_vulnerabilities() {
        let fixture = source_fixture();
        let root = fixture.path();
        let mut findings = Vec::new();
        let mut files = 0usize;
        for entry in walkdir::WalkDir::new(root) {
            let entry = entry.unwrap();
            if !entry.file_type().is_file() {
                continue;
            }
            files += 1;
            findings.extend(crate::scanners::scan_file(
                root,
                entry.path(),
                1024,
                true,
                true,
            ));
        }
        assert_eq!(files, 5, "expected fixture files, got {files}");
        for f in &findings {
            println!(
                "FINDING file={} rule={} cat={} line={} sev={}",
                f.file_path, f.rule_id, f.category, f.line, f.severity
            );
        }

        let secret_ids: Vec<&str> = findings
            .iter()
            .filter(|f| f.category == "secret")
            .map(|f| f.rule_id.as_str())
            .collect();
        let vuln_ids: Vec<&str> = findings
            .iter()
            .filter(|f| f.category == "vulnerability")
            .map(|f| f.rule_id.as_str())
            .collect();

        let expected = "github-token";
        assert!(
            secret_ids.contains(&expected),
            "expected secret rule {expected}, got: {secret_ids:?}"
        );
        for expected in [
            "js-eval",
            "js-exec-concat",
            "js-sql-concat",
            "py-eval",
            "py-pickle",
            "py-os-system",
            "py-sql-fstring",
        ] {
            assert!(
                vuln_ids.contains(&expected),
                "expected vuln rule {expected}, got: {vuln_ids:?}"
            );
        }

        // line numbers must be 1-based and file paths relative
        for f in &findings {
            assert!(f.line >= 1, "line must be >= 1");
            assert!(
                !f.file_path.starts_with('/'),
                "file path must be relative: {}",
                f.file_path
            );
            assert!(!f.recommendation.is_empty());
        }
    }

    #[test]
    fn fixture_lockfile_parses() {
        let dir = tempfile::tempdir().expect("lockfile tempdir");
        let path = dir.path().join("package-lock.json");
        std::fs::write(
            &path,
            r#"{
      "name": "fixture",
      "lockfileVersion": 2,
      "packages": {
        "": {"name": "fixture"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/express": {"version": "4.18.2"}
      }
    }"#,
        )
        .expect("write package lock");
        let deps = crate::deps::lockfiles::parse_lockfile(&path, "npm").expect("parse lockfile");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"lodash"), "lodash missing: {names:?}");
        assert!(names.contains(&"express"), "express missing: {names:?}");
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.15");
        assert_eq!(lodash.ecosystem, "npm");
    }

    #[test]
    fn dedupe_keeps_first() {
        let deps = vec![
            crate::models::Dependency {
                ecosystem: "npm".into(),
                name: "lodash".into(),
                version: "4.17.15".into(),
                lockfile: "a".into(),
            },
            crate::models::Dependency {
                ecosystem: "npm".into(),
                name: "lodash".into(),
                version: "4.17.15".into(),
                lockfile: "b".into(),
            },
        ];
        let out = crate::deps::lockfiles::dedupe_dependencies(deps);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn entropy_works() {
        let e = crate::scanners::secrets::shannon_entropy("abcdefghijklmnopqrstuvwxyz");
        let e2 =
            crate::scanners::secrets::shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert!(e < 5.0, "low entropy for alphabet: {e}");
        assert!(e2 > 4.0, "high entropy expected: {e2}");
    }

    /// Requires outbound network; marked ignored because the DSH sandbox blocks
    /// sockets from compiled binaries. Verified manually via curl (same contract).
    #[tokio::test]
    #[ignore = "sandbox blocks outbound sockets for compiled binaries"]
    async fn osv_client_live_query_lodash() {
        let http = reqwest::Client::new();
        let client = crate::deps::osv::OsvClient::new(http);
        let vulns = client
            .query_package("npm", "lodash", "4.17.15")
            .await
            .map_err(|e| panic!("OSV query failed: {e}"))
            .expect("OSV query should succeed");
        assert!(!vulns.is_empty(), "lodash@4.17.15 must have known vulns");
        let first = &vulns[0];
        assert!(!first.id.is_empty());
        assert_eq!(first.package_name, "lodash");
        assert_eq!(first.installed_version, "4.17.15");
        assert!(first.summary.len() > 0);
        // at least one vuln should carry CVE aliases or a severity
        let has_alias = vulns.iter().any(|v| !v.aliases.is_empty());
        let has_sev = vulns
            .iter()
            .any(|v| v.severity.is_some() || v.cvss_score.is_some());
        assert!(
            has_alias || has_sev,
            "expected aliases or severity in OSV records"
        );
    }

    #[test]
    fn placeholder_filtered() {
        assert!(crate::scanners::secrets::is_placeholder("changeme"));
        assert!(crate::scanners::secrets::is_placeholder("yourpassword123"));
        assert!(!crate::scanners::secrets::is_placeholder(
            "correcthorsebatterystaple"
        ));
    }
}
