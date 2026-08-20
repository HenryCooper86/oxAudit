mod ai;
mod agent;
mod binscan;
mod commands;
mod cve;
mod deps;
mod fs_utils;
mod models;
mod scanners;
mod sessions;
mod settings;

use tauri::Manager;

use commands::AppState;

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
    use std::path::Path;

    #[test]
    fn fixture_scan_finds_secrets_and_vulnerabilities() {
        let root = Path::new("/tmp/vc_fixture");
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
        assert!(files >= 5, "expected fixture files, got {files}");
        for f in &findings {
            println!("FINDING file={} rule={} cat={} line={} sev={}", f.file_path, f.rule_id, f.category, f.line, f.severity);
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

        for expected in [
            "aws-access-key-id",
            "aws-secret-key",
            "openai-api-key",
            "github-token",
            "private-key",
            "json-credential",
        ] {
            assert!(
                secret_ids.contains(&expected),
                "expected secret rule {expected}, got: {secret_ids:?}"
            );
        }
        for expected in ["js-eval", "js-exec-concat", "js-sql-concat", "py-eval", "py-pickle", "py-os-system", "py-sql-fstring"] {
            assert!(
                vuln_ids.contains(&expected),
                "expected vuln rule {expected}, got: {vuln_ids:?}"
            );
        }

        // line numbers must be 1-based and file paths relative
        for f in &findings {
            assert!(f.line >= 1, "line must be >= 1");
            assert!(!f.file_path.starts_with('/'), "file path must be relative: {}", f.file_path);
            assert!(!f.recommendation.is_empty());
        }
    }

    #[test]
    fn fixture_lockfile_parses() {
        let path = Path::new("/tmp/vc_fixture/package-lock.json");
        let deps = crate::deps::lockfiles::parse_lockfile(path, "npm").unwrap();
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
        let e2 = crate::scanners::secrets::shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
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
        let has_sev = vulns.iter().any(|v| v.severity.is_some() || v.cvss_score.is_some());
        assert!(has_alias || has_sev, "expected aliases or severity in OSV records");
    }

    #[test]
    fn placeholder_filtered() {
        assert!(crate::scanners::secrets::is_placeholder("changeme"));
        assert!(crate::scanners::secrets::is_placeholder("yourpassword123"));
        assert!(!crate::scanners::secrets::is_placeholder("correcthorsebatterystaple"));
    }
}
