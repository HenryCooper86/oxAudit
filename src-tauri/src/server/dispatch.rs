//! Command dispatch: the same command surface the desktop registers with
//! Tauri's `invoke_handler`, resolved from a JSON argument object instead.
//!
//! Each arm mirrors the frontend's `api.*` contract in `src/lib/api.ts` —
//! camelCase argument keys, identical result payloads, identical error
//! shapes. Scan-producing commands call the extracted engine functions, so
//! the desktop and the server run literally the same code; the rest call
//! the same `_inner` service helpers the Tauri commands call.

use crate::findings::service::ScanEventSink;
use crate::server::ServerContext;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub async fn dispatch(ctx: &ServerContext, cmd: &str, args: Value) -> Result<Value, Value> {
    match cmd {
        // ------------------------------------------------ source scanning
        "scan_project" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                options: crate::models::ScanOptions,
            }
            let a: Args = from_args(&args)?;
            let hub_events = ctx.events();
            ok_ce(
                crate::commands::scan_project_engine(
                    &ctx.app,
                    &ctx.findings,
                    &ctx.cve,
                    &ctx.rule_packs,
                    a.options,
                    &hub_events,
                )
                .await,
            )
        }
        "cancel_scan" => ok_st(crate::commands::cancel_scan_inner(&ctx.app)),
        "recheck_source_run" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                original_run_id: String,
                project_id: String,
            }
            let a: Args = from_args(&args)?;
            let hub_events = ctx.events();
            ok_ce(
                crate::commands::recheck_source_run_engine(
                    &ctx.app,
                    &ctx.findings,
                    &ctx.cve,
                    &ctx.rule_packs,
                    &a.original_run_id,
                    &a.project_id,
                    &hub_events,
                )
                .await,
            )
        }
        "inspect_source_project" => {
            let a = path_args(&args)?;
            ok_ce(crate::commands::inspect_source_project_inner(
                &ctx.findings, a.path,
            ))
        }
        "list_source_projects" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                #[serde(default = "default_u32_limit")]
                limit: u32,
            }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::list_source_projects_inner(
                &ctx.findings,
                a.limit,
            ))
        }
        "list_source_runs" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                project_id: String,
                #[serde(default = "default_u32_limit")]
                limit: u32,
            }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::list_source_runs_inner(
                &ctx.findings,
                &a.project_id,
                a.limit,
            ))
        }
        "load_source_run" => {
            let a = id_args(&args)?;
            ok_ce(crate::commands::load_source_run_inner(&ctx.findings, &a.id))
        }
        "compare_source_runs" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                current_run_id: String,
                baseline_run_id: String,
                #[serde(default)]
                require_valid_policy: Option<bool>,
            }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::compare_source_runs_inner(
                &ctx.findings,
                a.current_run_id,
                a.baseline_run_id,
                a.require_valid_policy,
            ))
        }
        "inspect_source_git" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                path: String,
                base_reference: String,
            }
            let a: Args = from_args(&args)?;
            let inspected = tokio::task::spawn_blocking(move || {
                crate::git_context::inspect(std::path::Path::new(&a.path), &a.base_reference)
            })
            .await
            .map_err(|_| "Git inspection could not complete".to_string())?;
            ok_st(inspected)
        }
        "retry_source_run_save" => {
            let a = id_args(&args)?;
            ok_ce(crate::commands::retry_source_run_save_inner(
                &ctx.findings,
                &a.id,
            ))
        }
        "save_finding_review" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::findings::domain::ReviewRequest,
            }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::save_finding_review_inner(&ctx.findings, a.request))
        }
        "delete_finding_review" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::findings::domain::ReviewRequest,
            }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::delete_finding_review_inner(&ctx.findings, a.request))
        }
        "save_finding_reviews" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                requests: Vec<crate::findings::domain::ReviewRequest>,
            }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::save_finding_reviews_inner(&ctx.findings, a.requests))
        }

        // --------------------------------------------------- dependencies
        "scan_dependencies" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                path: String,
                #[serde(default)]
                offline: bool,
                #[serde(default)]
                advisory_db_path: Option<String>,
            }
            let a: Args = from_args(&args)?;
            let hub_events = ctx.events();
            ok_st(
                crate::commands::dependencies::scan_dependencies_engine(
                    &ctx.app,
                    &ctx.findings,
                    &ctx.cache_dir,
                    &hub_events,
                    a.path,
                    a.offline,
                    a.advisory_db_path,
                )
                .await,
            )
        }
        "cancel_dependency_scan" => {
            ctx.app
                .cancel_dependency_scan
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Value::Null)
        }
        "find_lockfiles" => {
            let a = path_args(&args)?;
            ok_st(crate::commands::dependencies::find_lockfiles_inner(
                &ctx.app,
                a.path,
            ))
        }

        // --------------------------------------------------- git history
        "scan_history_secrets" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                path: String,
                #[serde(default)]
                validate_secrets: Option<bool>,
            }
            let a: Args = from_args(&args)?;
            ok_st(
                crate::commands::history::scan_history_secrets_engine(
                    &ctx.app.http,
                    a.path,
                    a.validate_secrets,
                )
                .await,
            )
        }

        // ------------------------------------------------------ binaries
        "binary_tool_status" => {
            ok_st(crate::commands::dependencies::binary_tool_status_engine(&ctx.app).await)
        }
        "scan_binaries" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::binscan::run::BinaryScanRequest,
                #[serde(default)]
                use_grype: Option<bool>,
            }
            let a: Args = from_args(&args)?;
            let scratch_dir = ctx.cache_dir.join("binscan");
            let progress: std::sync::Arc<dyn Fn(String) + Send + Sync> = {
                let hub_events = ctx.events();
                std::sync::Arc::new(move |line: String| {
                    let _ = hub_events.emit("binscan://progress", Value::from(line));
                })
            };
            let run_events = ctx.run_events();
            let hub_events = ctx.events();
            ok_st(
                crate::commands::dependencies::scan_binaries_engine(
                    &ctx.app,
                    &ctx.findings,
                    Some(&ctx.cve),
                    &scratch_dir,
                    &ctx.cache_dir,
                    &run_events,
                    &hub_events,
                    progress,
                    a.request,
                    a.use_grype,
                )
                .await,
            )
        }
        "cancel_binary_scan" => {
            ctx.app
                .cancel_binary_scan
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(Value::Null)
        }
        "refresh_binary_database" => {
            let scratch_dir = ctx.cache_dir.join("binscan");
            let progress: std::sync::Arc<dyn Fn(String) + Send + Sync> = {
                let hub_events = ctx.events();
                std::sync::Arc::new(move |line: String| {
                    let _ = hub_events.emit("binscan://progress", Value::from(line));
                })
            };
            ok_st(
                crate::commands::dependencies::refresh_binary_database_engine(
                    &ctx.app,
                    &scratch_dir,
                    &ctx.cache_dir,
                    progress,
                )
                .await,
            )
        }

        // --------------------------------------------------------- image
        "scan_image" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::commands::image::ImageScanRequest,
            }
            let a: Args = from_args(&args)?;
            let progress: std::sync::Arc<dyn Fn(String) + Send + Sync> = {
                let hub_events = ctx.events();
                std::sync::Arc::new(move |line: String| {
                    let _ = hub_events.emit("image://progress", Value::from(line));
                })
            };
            let hub_events = ctx.events();
            ok_st(
                crate::commands::image::scan_image_engine(
                    &ctx.app,
                    Some(&ctx.cve),
                    &ctx.cache_dir,
                    progress,
                    &hub_events,
                    a.request,
                )
                .await,
            )
        }
        "cancel_image_scan" => {
            ctx.app
                .cancel_binary_scan
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Value::Null)
        }

        // ------------------------------------------------- canonical runs
        "list_canonical_runs" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                #[serde(default)]
                kind: Option<String>,
                #[serde(default)]
                limit: Option<usize>,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::list_canonical_runs_inner(
                &ctx.findings,
                a.kind,
                a.limit,
            ))
        }
        "load_canonical_projection" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::reporting::load_canonical_projection_inner(
                &ctx.findings,
                a.id,
            ))
        }
        "load_inventory" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::reporting::load_inventory_inner(
                &ctx.findings, a.id,
            ))
        }

        // ------------------------------------------- import/export/reports
        "preview_report_import" => {
            let a = path_args(&args)?;
            ok_st(crate::commands::reporting::preview_report_import_inner(
                &ctx.findings,
                a.path,
            ))
        }
        "import_inventory_report" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                path: String,
                expected_sha256: String,
            }
            let a: Args = from_args(&args)?;
            let run_events = ctx.run_events();
            ok_st(crate::commands::reporting::import_inventory_report_inner(
                &ctx.findings,
                &run_events,
                a.path,
                a.expected_sha256,
            ))
        }
        "import_external_report" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                path: String,
                expected_sha256: String,
            }
            let a: Args = from_args(&args)?;
            let run_events = ctx.run_events();
            ok_st(crate::commands::reporting::import_external_report_inner(
                &ctx.findings,
                &run_events,
                a.path,
                a.expected_sha256,
            ))
        }
        "preview_run_export" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                run_id: String,
                format: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::preview_run_export_inner(
                &ctx.findings,
                a.run_id,
                a.format,
            ))
        }
        "write_run_export" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                run_id: String,
                format: String,
                output_path: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::write_run_export_inner(
                &ctx.findings,
                a.run_id,
                a.format,
                a.output_path,
            ))
        }
        "list_verification_claims" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                #[serde(default)]
                run_id: Option<String>,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::list_verification_claims_inner(
                &ctx.findings,
                a.run_id,
            ))
        }
        "list_verifications" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                #[serde(default)]
                finding_id: Option<String>,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::list_verifications_inner(
                &ctx.findings,
                a.finding_id,
            ))
        }
        "verify_finding" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                finding_id: String,
                verifier_id: String,
                result: String,
                limitation: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::verify_finding_inner(
                &ctx.findings,
                a.finding_id,
                a.verifier_id,
                a.result,
                a.limitation,
            ))
        }

        // ------------------------------------------------------- advisory db
        "advisory_db_status" => {
            let a = path_args(&args)?;
            ok_st(crate::commands::advisories::advisory_db_status(a.path))
        }
        "default_advisory_db_path" => Ok(Value::from(
            ctx.data_dir
                .join("advisories.sqlite3")
                .to_string_lossy()
                .replace('\\', "/"),
        )),
        "advisory_db_update" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                path: String,
                #[serde(default)]
                ecosystems: Vec<String>,
                #[serde(default)]
                source: Option<String>,
            }
            let a: Args = from_args(&args)?;
            let path = std::path::Path::new(&a.path);
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    crate::private_storage::ensure_private_dir(parent).map_err(st_err)?;
                }
            }
            let mut store = crate::advisories::store::AdvisoryDb::open(path)
                .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
            let hub_events = ctx.events();
            ok_st(
                crate::commands::advisories::advisory_db_update_engine(
                    &ctx.app.http,
                    &mut store,
                    a.ecosystems,
                    a.source,
                    &hub_events,
                )
                .await,
            )
        }

        // ---------------------------------------------------------- VEX
        "vex_claim_sets" => {
            ok_st(crate::commands::vex::vex_claim_sets_inner(&ctx.findings))
        }
        "vex_grant_trust" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                content_sha256: String,
                granted_by: String,
                #[serde(default)]
                note: Option<String>,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::vex::vex_grant_trust_inner(
                &ctx.findings,
                a.content_sha256,
                a.granted_by,
                a.note,
            ))
        }
        "vex_revoke_trust" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::vex::vex_revoke_trust_inner(&ctx.findings, a.id))
        }
        "vex_suggest" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::vex::vex_suggest_inner(&ctx.findings, a.id))
        }

        // -------------------------------------------------- rules/quality
        "rule_library_status" => {
            ok_st(crate::commands::quality::rule_library_status())
        }
        "validate_rule_pack" => {
            let a = path_args(&args)?;
            ok_st(crate::commands::quality::validate_rule_pack(a.path))
        }
        "install_rule_pack" => {
            let a = path_args(&args)?;
            ok_st(crate::commands::quality::install_rule_pack_inner(
                &ctx.rule_packs,
                a.path,
            ))
        }
        "list_installed_rule_packs" => {
            ok_st(crate::commands::quality::list_installed_rule_packs_inner(
                &ctx.rule_packs,
            ))
        }
        "set_rule_pack_enabled" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                id: String,
                enabled: bool,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::quality::set_rule_pack_enabled_inner(
                &ctx.rule_packs,
                a.id,
                a.enabled,
            ))
        }
        "remove_rule_pack" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::quality::remove_rule_pack_inner(
                &ctx.rule_packs,
                a.id,
            ))
        }
        "quality_status" => {
            ok_st(crate::commands::quality::quality_status_inner(&ctx.findings))
        }
        "external_benchmark" => {
            let a = path_args(&args)?;
            ok_st(crate::commands::quality::external_benchmark(a.path).await)
        }
        "list_compiled_grammars" => {
            Ok(serde_json::to_value(crate::commands::quality::list_compiled_grammars())
                .map_err(ser_err)?)
        }
        "list_data_sources" => {
            ok_st(crate::commands::quality::list_data_sources_inner(&ctx.findings))
        }
        "refresh_data_source" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                provider_id: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(
                crate::commands::quality::refresh_data_source_inner(
                    a.provider_id,
                    &ctx.app,
                    &ctx.findings,
                    Some(&ctx.data_dir),
                )
                .await,
            )
        }

        // ----------------------------------------------------- CVE research
        "search_cves" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                query: String,
                start_index: usize,
                per_page: usize,
                #[serde(default)]
                recent_days: Option<u64>,
            }
            let a: Args = from_args(&args)?;
            ok_st(
                crate::commands::cve::search_cves_inner(
                    &ctx.cve,
                    &ctx.app,
                    a.query,
                    a.start_index,
                    a.per_page,
                    a.recent_days,
                )
                .await,
            )
        }
        "cve_detail" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::cve::cve_detail_inner(&ctx.cve, &ctx.app, a.id).await)
        }
        "osv_package_vulns" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                ecosystem: String,
                name: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(
                crate::commands::cve::osv_package_vulns_inner(&ctx.cve, a.ecosystem, a.name)
                    .await,
            )
        }

        // ------------------------------------------------------ schedules
        "list_scan_schedules" => {
            let store = ctx.schedules.store().map_err(st_err)?;
            Ok(serde_json::to_value(
                store
                    .list()
                    .into_iter()
                    .map(|record| crate::commands::schedule::ScanScheduleStatus {
                        next_due_at: crate::schedule_store::next_due(&record)
                            .map(|when| when.to_rfc3339()),
                        record,
                    })
                    .collect::<Vec<_>>(),
            )
            .map_err(ser_err)?)
        }
        "set_scan_schedule" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                project_id: String,
                canonical_path: String,
                display_name: String,
                interval_hours: u32,
                enabled: bool,
            }
            let a: Args = from_args(&args)?;
            let record = ctx
                .schedules
                .store()
                .map_err(st_err)?
                .upsert(
                    &a.project_id,
                    &a.canonical_path,
                    &a.display_name,
                    a.interval_hours,
                    a.enabled,
                )
                .map_err(st_err)?;
            Ok(serde_json::to_value(record).map_err(ser_err)?)
        }
        "remove_scan_schedule" => {
            let a = id_args(&args)?;
            ctx.schedules
                .store()
                .map_err(st_err)?
                .remove(&a.id)
                .map_err(st_err)?;
            Ok(Value::Null)
        }
        "run_scan_now" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                project_id: String,
                canonical_path: String,
            }
            let a: Args = from_args(&args)?;
            let hub_events = ctx.events();
            let hub = ctx.hub.clone();
            let completed_project_id = a.project_id.clone();
            let completed_path = a.canonical_path.clone();
            let publish = move |result: &Result<crate::findings::domain::ScanRunDetail, crate::findings::error::CommandError>| {
                hub.publish(
                    "schedule://completed",
                    crate::commands::schedule::completion_payload(&completed_project_id, &completed_path, result),
                );
            };
            ok_ce(
                crate::commands::schedule::run_scheduled_scan_engine(
                    &ctx.app,
                    &ctx.findings,
                    &ctx.cve,
                    Some(&ctx.rule_packs),
                    &hub_events,
                    &publish,
                    crate::commands::schedule::ScheduledScanTarget {
                        canonical_path: &a.canonical_path,
                        project_id: &a.project_id,
                        schedules: ctx.schedules.store().ok(),
                    },
                )
                .await,
            )
        }

        // ------------------------------------------------------- settings
        "set_active_project" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                #[serde(default)]
                path: Option<String>,
            }
            let a: Args = from_args(&args)?;
            let project = crate::commands::active_project_path(a.path)?;
            *ctx.app.active_project.lock().unwrap() = project;
            Ok(Value::Null)
        }
        "load_settings" => {
            let settings = crate::settings::load_secure_from_path(
                &ctx.settings_path(),
                ctx.app.credentials.as_ref(),
            )
            .map_err(ce_err)?;
            *ctx.app.settings.lock().unwrap() = settings.clone();
            ok(settings)
        }
        "save_settings" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::models::SaveSettingsRequest,
            }
            let a: Args = from_args(&args)?;
            let result = crate::settings::save_secure_to_path(
                &ctx.settings_path(),
                ctx.app.credentials.as_ref(),
                a.request,
            )
            .map_err(ce_err)?;
            *ctx.app.settings.lock().unwrap() = result.settings.clone();
            ok(result)
        }
        "collect_diagnostics" => {
            let ai_configured = ctx
                .app
                .settings
                .lock()
                .map(|settings| settings.ai.enabled && !settings.ai.base_url.trim().is_empty())
                .unwrap_or(false);
            let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
            ok(crate::observability::collect(ai_configured, home.as_deref()))
        }

        // ------------------------------------------------------- sessions
        "session_list" => ok_st(ctx.session_store()?.list()),
        "session_create" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                #[serde(default)]
                title: Option<String>,
                #[serde(default)]
                project_path: Option<String>,
            }
            let a: Args = from_args(&args)?;
            ok_st(ctx.session_store()?.create(a.title, a.project_path))
        }
        "session_get_messages" => {
            let a = id_args(&args)?;
            ok_st(ctx.session_store()?.get_messages(&a.id))
        }
        "session_append" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                session_id: String,
                message: crate::sessions::StoredMessage,
            }
            let a: Args = from_args(&args)?;
            ok_st(ctx.session_store()?.append(&a.session_id, &a.message))
        }
        "session_rename" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                session_id: String,
                title: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(ctx.session_store()?.rename(&a.session_id, a.title))
        }
        "session_delete" => {
            let a = id_args(&args)?;
            ok_st(ctx.session_store()?.delete(&a.id))
        }
        "session_truncate" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                session_id: String,
                keep_count: usize,
            }
            let a: Args = from_args(&args)?;
            ok_st(ctx.session_store()?.truncate(&a.session_id, a.keep_count))
        }

        // ---------------------------------------------------- compliance
        "list_compliance_profiles" => {
            ok_st(crate::compliance::list_compliance_profiles())
        }
        "run_compliance_assessment" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::compliance::RunComplianceRequest,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::compliance::run_compliance_assessment_inner(
                &ctx.findings,
                a.request,
            ))
        }
        "list_compliance_assessments" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                #[serde(default = "default_usize_limit")]
                limit: usize,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::compliance::list_compliance_assessments_inner(
                &ctx.findings,
                Some(a.limit),
            ))
        }
        "load_compliance_assessment" => {
            let a = id_args(&args)?;
            ok_st(crate::compliance::load_compliance_assessment_inner(
                &ctx.findings,
                a.id,
            ))
        }
        "save_compliance_review" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::compliance::SaveComplianceReviewRequest,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::compliance::save_compliance_review_inner(
                &ctx.findings,
                a.request,
            ))
        }
        "preview_compliance_report" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::compliance::ComplianceReportRequest,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::compliance::preview_compliance_report_inner(
                &ctx.findings,
                a.request,
            ))
        }
        "write_compliance_report" => {
            // The frontend merges outputPath into the request before sending,
            // exactly as it does for the desktop command.
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::compliance::WriteComplianceReportRequest,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::compliance::write_compliance_report_inner(
                &ctx.findings,
                a.request,
            ))
        }

        // The AI assistant surface needs the streaming chat engine, which is
        // still wired to the Tauri handle. It is refused here rather than
        // silently unavailable, so the GUI states the reason.
        "stream_chat" | "research_cve" | "test_ai" | "test_ai_with" => {
            Err(disabled("The AI assistant is not available through the headless server yet; run the desktop app or the CLI for AI research."))
        }
        "cancel_chat" | "steer_chat" | "todo_list" | "respond_permission"
        | "respond_interaction" | "get_conversation_usage" | "get_total_usage" => {
            Ok(Value::Null)
        }
        "open_scan_finding" => Err(disabled(
            "Opening files in an editor requires the desktop app; copy the path instead.",
        )),

        other => Err(disabled(&format!(
            "Unknown command `{other}`. The headless server serves the same command surface as the desktop app's invoke handler; this name is not part of it."
        ))),
    }
}

// ---------------------------------------------------------------- helpers

fn default_u32_limit() -> u32 {
    50
}

fn default_usize_limit() -> usize {
    50
}

fn from_args<A: DeserializeOwned>(args: &Value) -> Result<A, Value> {
    serde_json::from_value(args.clone())
        .map_err(|error| Value::String(format!("invalid arguments: {error}")))
}

struct PathArgs {
    path: String,
}

fn path_args(args: &Value) -> Result<PathArgs, Value> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct A {
        path: String,
    }
    Ok(PathArgs {
        path: from_args::<A>(args)?.path,
    })
}

struct IdArgs {
    id: String,
}

fn id_args(args: &Value) -> Result<IdArgs, Value> {
    // The desktop commands name this parameter per command (runId, id,
    // findingId...); accept any single string-valued identity field.
    for key in [
        "runId",
        "id",
        "assessmentId",
        "sessionId",
        "contentSha256",
        "projectId",
        "retryToken",
    ] {
        if let Some(value) = args.get(key).and_then(Value::as_str) {
            return Ok(IdArgs {
                id: value.to_string(),
            });
        }
    }
    Err(Value::String("missing identifier argument".into()))
}

fn disabled(message: &str) -> Value {
    serde_json::json!({
        "code": "dataOperationFailed",
        "message": message,
        "detail": null,
        "retryable": false,
    })
}

fn ok<T: serde::Serialize>(value: T) -> Result<Value, Value> {
    serde_json::to_value(value).map_err(ser_err)
}

fn ok_ce<T: serde::Serialize>(
    r: Result<T, crate::findings::error::CommandError>,
) -> Result<Value, Value> {
    match r {
        Ok(value) => serde_json::to_value(value).map_err(ser_err),
        Err(error) => Err(ce_err(error)),
    }
}

fn ok_st<T: serde::Serialize>(r: Result<T, String>) -> Result<Value, Value> {
    r.map(|value| serde_json::to_value(value).unwrap_or(Value::Null))
        .map_err(Value::String)
}

fn ce_err(error: crate::findings::error::CommandError) -> Value {
    let fallback = Value::String(error.to_string());
    serde_json::to_value(error).unwrap_or(fallback)
}

fn st_err(error: String) -> Value {
    Value::String(error)
}

fn ser_err<E: std::fmt::Display>(error: E) -> Value {
    Value::String(format!("result could not be serialized: {error}"))
}
