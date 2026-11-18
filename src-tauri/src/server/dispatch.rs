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
                #[serde(default)]
                operation_id: Option<String>,
            }
            let a: Args = from_args(&args)?;
            let hub_events = ctx.events();
            ok_ce(
                crate::commands::scan_source_engine_scoped(
                    &ctx.app,
                    &ctx.findings,
                    &ctx.cve,
                    &ctx.rule_packs,
                    a.options.clone(),
                    std::path::Path::new(&a.options.path),
                    a.operation_id.as_deref(),
                    None,
                    &hub_events,
                )
                .await,
            )
        }
        "cancel_scan" => ok_st(crate::commands::cancel_scan_inner(&ctx.app)),
        "scan_work_status" => ok_st(ctx.app.scan_work.snapshot()),
        "cancel_scan_work" => {
            let id = args.get("operationId").and_then(Value::as_str).ok_or_else(|| Value::String("operationId is required".into()))?;
            let cancelled = ctx.app.scan_work.cancel(Some(id), &[]).map_err(Value::String)?;
            if cancelled { let _ = ctx.events().emit("work://changed", serde_json::to_value(ctx.app.scan_work.snapshot().map_err(Value::String)?).map_err(|error| Value::String(error.to_string()))?); }
            Ok(Value::Bool(cancelled))
        }
        "recheck_source_run" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                original_run_id: String,
                project_id: String,
                #[serde(default)]
                operation_id: Option<String>,
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
                    a.operation_id.as_deref(),
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
                #[serde(default)]
                offset: u32,
            }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::list_source_projects_page_inner(
                &ctx.findings,
                a.limit,
                a.offset,
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
        "load_source_run_metadata" => {
            let a = id_args(&args)?;
            ok_ce(crate::commands::load_source_run_metadata_inner(&ctx.findings, &a.id))
        }
        "load_source_run_page" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args { run_id: String, query: Option<crate::findings::domain::SourceFindingsQuery> }
            let a: Args = from_args(&args)?;
            ok_ce(crate::commands::load_source_run_page_inner(&ctx.findings, &a.run_id, a.query.unwrap_or_default()))
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
                #[serde(default)]
                operation_id: Option<String>,
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
                    a.operation_id,
                )
                .await,
            )
        }
        "cancel_dependency_scan" => {
            ctx.app.scan_work.cancel(None, &[crate::scan_work::WorkKind::Dependencies]).map_err(Value::String)?;
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
                #[serde(default)]
                operation_id: Option<String>,
            }
            let a: Args = from_args(&args)?;
            ok_st(
                crate::commands::history::scan_history_secrets_engine(
                    &ctx.app,
                    &ctx.findings,
                    &ctx.events(),
                    a.path,
                    a.validate_secrets,
                    a.operation_id,
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
                #[serde(default)]
                operation_id: Option<String>,
            }
            let a: Args = from_args(&args)?;
            let scratch_dir = ctx.cache_dir.join("binscan");
            let progress: std::sync::Arc<dyn Fn(Value) + Send + Sync> = {
                let hub_events = ctx.events();
                std::sync::Arc::new(move |payload: Value| {
                    let _ = hub_events.emit("binscan://progress", payload);
                })
            };
            let hub_events = ctx.events();
            ok_st(
                crate::commands::dependencies::scan_binaries_engine(
                    &ctx.app,
                    &ctx.findings,
                    Some(&ctx.cve),
                    &scratch_dir,
                    &ctx.cache_dir,
                    &hub_events,
                    progress,
                    a.request,
                    a.use_grype,
                    a.operation_id,
                )
                .await,
            )
        }
        "cancel_binary_scan" => {
            ctx.app.scan_work.cancel(None, &[crate::scan_work::WorkKind::Binary]).map_err(Value::String)?;
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
                    &ctx.events(),
                    args.get("operationId").and_then(Value::as_str).map(str::to_owned),
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
            let progress: std::sync::Arc<dyn Fn(Value) + Send + Sync> = {
                let hub_events = ctx.events();
                std::sync::Arc::new(move |payload: Value| {
                    let _ = hub_events.emit("image://progress", payload);
                })
            };
            let hub_events = ctx.events();
            ok_st(
                crate::commands::image::scan_image_engine(
                    &ctx.app,
                    &ctx.findings,
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
            ctx.app.scan_work.cancel(None, &[crate::scan_work::WorkKind::Image]).map_err(Value::String)?;
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
        "load_canonical_projection_metadata" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::reporting::load_canonical_projection_metadata_inner(&ctx.findings, a.id))
        }
        "load_canonical_projection_page" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args { run_id: String, section: String, query: Option<crate::findings::domain::ResultPageQuery> }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::load_canonical_projection_page_inner(&ctx.findings, a.run_id, a.section, a.query.unwrap_or_default()))
        }
        "load_inventory" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::reporting::load_inventory_inner(
                &ctx.findings, a.id,
            ))
        }
        "list_inventory_runs" => {
            #[derive(serde::Deserialize)]
            struct Args { query: Option<crate::findings::domain::ResultPageQuery> }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::list_inventory_runs_inner(&ctx.findings, a.query.unwrap_or_default()))
        }
        "load_inventory_page" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args { run_id: String, query: Option<crate::findings::domain::ResultPageQuery> }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::reporting::load_inventory_page_inner(&ctx.findings, a.run_id, a.query.unwrap_or_default()))
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
        // ------------------------------------------- signature packs / YARA
        "validate_signature_pack" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                kind: crate::sigpacks::PackKind,
                path: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::sigpacks::validate_signature_pack_inner(a.kind, &a.path).await)
        }
        "install_signature_pack" => {
            #[derive(serde::Deserialize)]
            struct Args {
                request: crate::commands::sigpacks::InstallSignaturePackRequest,
            }
            let a: Args = from_args(&args)?;
            ok_st(
                crate::commands::sigpacks::install_signature_pack_inner(&ctx.sig_packs, a.request)
                    .await,
            )
        }
        "list_signature_packs" => ok_st(
            crate::commands::sigpacks::list_signature_packs_inner(&ctx.sig_packs),
        ),
        "set_signature_pack_enabled" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                id: String,
                enabled: bool,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::sigpacks::set_signature_pack_enabled_inner(
                &ctx.sig_packs,
                &a.id,
                a.enabled,
            ))
        }
        "remove_signature_pack" => {
            let a = id_args(&args)?;
            ok_st(crate::commands::sigpacks::remove_signature_pack_inner(
                &ctx.sig_packs,
                &a.id,
            ))
        }
        "scan_yara" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::yara::YaraScanRequest,
            }
            let a: Args = from_args(&args)?;
            let progress: std::sync::Arc<dyn Fn(Value) + Send + Sync> = {
                let hub_events = ctx.events();
                std::sync::Arc::new(move |payload: Value| {
                    let _ = hub_events.emit("yara://progress", payload);
                })
            };
            let hub_events = ctx.events();
            ok_st(
                crate::commands::yara::scan_yara_engine(
                    &ctx.app.scan_work,
                    &ctx.findings,
                    &ctx.sig_packs,
                    &hub_events,
                    progress,
                    a.request,
                )
                .await,
            )
        }
        "scan_templates" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request: crate::template::TemplateScanRequest,
            }
            let a: Args = from_args(&args)?;
            // Live targets make the server send traffic from its own network
            // position, so a token holder could use it to probe that network.
            // Refused unless the operator opted in at startup; checked before
            // the request is validated, its targets parsed, or anything is
            // resolved, opened or stored. Local-path scans are unaffected.
            if !a.request.targets.is_empty() && !ctx.allow_live_targets {
                return Err(st_err(LIVE_TARGETS_REFUSED.into()));
            }
            let live_settings = ctx
                .app
                .settings
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .live_scan
                .clone();
            let progress: std::sync::Arc<dyn Fn(Value) + Send + Sync> = {
                let hub_events = ctx.events();
                std::sync::Arc::new(move |payload: Value| {
                    let _ = hub_events.emit("template://progress", payload);
                })
            };
            let hub_events = ctx.events();
            ok_st(
                crate::commands::template::scan_templates_engine(
                    &ctx.app.scan_work,
                    &ctx.findings,
                    &ctx.sig_packs,
                    &hub_events,
                    progress,
                    a.request,
                    &live_settings,
                )
                .await,
            )
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
                    .map_err(st_err)?
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
        "cancel_chat" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                run_id: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::assistant::cancel_chat_inner(
                &ctx.app, &a.run_id,
            ))
        }
        "steer_chat" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                run_id: String,
                message: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::assistant::steer_chat_inner(
                &ctx.app, &a.run_id, &a.message,
            ))
        }
        "todo_list" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                conversation_id: String,
            }
            let a: Args = from_args(&args)?;
            ok(crate::commands::assistant::todo_list_inner(
                &ctx.app,
                &a.conversation_id,
            ))
        }
        "respond_permission" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request_id: String,
                approve: bool,
            }
            let a: Args = from_args(&args)?;
            crate::commands::assistant::respond_permission_inner(&ctx.app, &a.request_id, a.approve);
            ok(Value::Null)
        }
        "respond_interaction" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                request_id: String,
                answers: Value,
            }
            let a: Args = from_args(&args)?;
            crate::commands::assistant::respond_interaction_inner(
                &ctx.app,
                &a.request_id,
                a.answers,
            );
            ok(Value::Null)
        }
        "get_conversation_usage" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Args {
                conversation_id: String,
            }
            let a: Args = from_args(&args)?;
            ok_st(crate::commands::assistant::get_conversation_usage_inner(
                &ctx.config_dir.join("usage.json"),
                &a.conversation_id,
            ))
        }
        "get_total_usage" => ok_st(crate::commands::assistant::get_total_usage_inner(
            &ctx.config_dir.join("usage.json"),
        )),
        "open_scan_finding" => Err(disabled(
            "Opening files in an editor requires the desktop app; copy the path instead.",
        )),

        other => Err(disabled(&format!(
            "Unknown command `{other}`. The headless server serves the same command surface as the desktop app's invoke handler; this name is not part of it."
        ))),
    }
}

// ---------------------------------------------------------------- helpers

/// The refusal a live-target template scan gets from a server that was not
/// started with live targets allowed.
pub(crate) const LIVE_TARGETS_REFUSED: &str = "This server does not run template scans against live targets: it would send traffic from the server's network position. Start oxaudit-server with --allow-live-targets (or OXAUDIT_SERVER_ALLOW_LIVE_TARGETS=1) to allow it. Local-path template scans work without it.";

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_context() -> (ServerContext, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        let config_dir = dir.path().join("config");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        let app = crate::commands::AppState::new();
        let cve = crate::cve::CveState::new(app.http.clone());
        let ctx = ServerContext {
            app,
            findings: crate::initialize_findings_state(&data_dir, chrono::Utc::now()),
            cve,
            rule_packs: crate::rulepack_store::RulePacksState::unavailable("test".into()),
            sig_packs: crate::sigpacks::SigPacksState::unavailable("test".into()),
            schedules: crate::schedule_store::ScheduleState::unavailable("test".into()),
            hub: Arc::new(crate::server::hub::EventHub::new()),
            data_dir,
            cache_dir: dir.path().join("cache"),
            config_dir,
            web_root: None,
            allow_live_targets: false,
        };
        (ctx, dir)
    }

    #[tokio::test]
    async fn save_settings_rejects_invalid_live_scan_settings_without_storing_them() {
        let (ctx, _dir) = test_context();
        let request = |live_scan: serde_json::Value| {
            let mut settings = serde_json::to_value(crate::models::AppSettings::default()).unwrap();
            settings["liveScan"] = live_scan;
            serde_json::json!({
                "request": {
                    "settings": settings,
                    "aiApiKey": {"action": "unchanged"},
                    "nvdApiKey": {"action": "unchanged"},
                }
            })
        };
        let defaults = serde_json::to_value(crate::models::LiveScanSettings::default()).unwrap();
        let with = |field: &str, value: serde_json::Value| {
            let mut live = defaults.clone();
            live[field] = value;
            request(live)
        };
        for (args, expected) in [
            (
                with(
                    "proxy",
                    serde_json::json!("http://alice:s3cret@proxy.invalid:3128"),
                ),
                "user name or password",
            ),
            (
                with("proxy", serde_json::json!("socks5://proxy.invalid:1080")),
                "http:// or https://",
            ),
            (
                with("proxy", serde_json::json!("not a url")),
                "not a valid URL",
            ),
            (
                with("requestsPerSecond", serde_json::json!(0)),
                "requests per second",
            ),
            (
                with("requestsPerSecond", serde_json::json!(1001)),
                "between 1 and 1000",
            ),
            (
                with("perHostConcurrency", serde_json::json!(101)),
                "per host",
            ),
            (with("timeoutSeconds", serde_json::json!(121)), "timeout"),
            (
                with("maxResponseKb", serde_json::json!(32769)),
                "response cap",
            ),
            (with("maxRequests", serde_json::json!(0)), "request budget"),
        ] {
            let error = dispatch(&ctx, "save_settings", args)
                .await
                .expect_err("invalid live-scan settings are refused");
            let text = error.to_string();
            assert!(text.contains(expected), "{expected}: {text}");
            assert!(!text.contains("s3cret"), "{text}");
        }
        assert!(
            !ctx.settings_path().exists(),
            "nothing was written for a refused save"
        );
    }

    #[tokio::test]
    async fn schedule_read_failures_are_errors_not_empty_or_partial_lists() {
        for damage in [
            "DROP TABLE scan_schedules",
            "UPDATE scan_schedules SET last_started_at = X'FF' WHERE project_id = 'broken'",
        ] {
            let (mut ctx, dir) = test_context();
            let path = dir.path().join("schedules.sqlite3");
            let store = crate::schedule_store::ScheduleStore::open(&path).unwrap();
            store.upsert("healthy", "/healthy", "A", 24, true).unwrap();
            store.upsert("broken", "/broken", "B", 24, true).unwrap();
            ctx.schedules = crate::schedule_store::ScheduleState::available(store);
            rusqlite::Connection::open(path)
                .unwrap()
                .execute_batch(damage)
                .unwrap();
            let result = dispatch(&ctx, "list_scan_schedules", serde_json::json!({})).await;
            assert!(
                result.is_err(),
                "schedule storage damage must be visible: {result:?}"
            );
        }
    }

    #[cfg(feature = "yara")]
    #[tokio::test]
    async fn signature_packs_and_yara_scans_run_through_dispatch() {
        let (mut ctx, dir) = test_context();
        // Without a store, pack commands say so and a scan with no rules fails.
        let unavailable = dispatch(&ctx, "list_signature_packs", serde_json::json!({})).await;
        assert!(unavailable.is_err());

        ctx.sig_packs =
            crate::sigpacks::SigPacksState::open_beside(&ctx.data_dir.join("rule-packs.sqlite3"));
        let rules = dir.path().join("alpha.yar");
        std::fs::write(
            &rules,
            "rule marker_alpha { strings: $a = \"OXAUDIT-FIXTURE-ALPHA\" condition: $a }",
        )
        .unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("hit.bin"), b"..OXAUDIT-FIXTURE-ALPHA..").unwrap();

        let none = dispatch(
            &ctx,
            "scan_yara",
            serde_json::json!({"request": {"path": target.to_string_lossy()}}),
        )
        .await;
        assert!(
            none.unwrap_err()
                .as_str()
                .unwrap()
                .contains("No YARA rules"),
            "a scan without rules must fail, not report no matches"
        );

        let preview = dispatch(
            &ctx,
            "validate_signature_pack",
            serde_json::json!({"kind": "yara", "path": rules.to_string_lossy()}),
        )
        .await
        .unwrap();
        assert_eq!(preview["ruleCount"], 1);
        assert_eq!(preview["fileCount"], 1);

        let installed = dispatch(
            &ctx,
            "install_signature_pack",
            serde_json::json!({"request": {
                "kind": "yara", "path": rules.to_string_lossy(),
                "name": "Alpha", "license": "Apache-2.0"
            }}),
        )
        .await
        .unwrap();
        let id = installed["id"].as_str().unwrap().to_owned();
        let listed = dispatch(&ctx, "list_signature_packs", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 1);

        let scan = dispatch(
            &ctx,
            "scan_yara",
            serde_json::json!({"request": {"path": target.to_string_lossy()}}),
        )
        .await
        .unwrap();
        assert_eq!(scan["state"], "completed");
        assert_eq!(scan["matches"].as_array().unwrap().len(), 1);
        assert_eq!(scan["matches"][0]["pack"], id);
        assert_eq!(scan["matches"][0]["strings"][0]["offset"], 2);

        dispatch(
            &ctx,
            "set_signature_pack_enabled",
            serde_json::json!({"id": id, "enabled": false}),
        )
        .await
        .unwrap();
        assert!(dispatch(
            &ctx,
            "scan_yara",
            serde_json::json!({"request": {"path": target.to_string_lossy()}}),
        )
        .await
        .is_err());
        dispatch(&ctx, "remove_signature_pack", serde_json::json!({"id": id}))
            .await
            .unwrap();
        let listed = dispatch(&ctx, "list_signature_packs", serde_json::json!({}))
            .await
            .unwrap();
        assert!(listed.as_array().unwrap().is_empty());
    }

    #[cfg(feature = "templates")]
    #[tokio::test]
    async fn template_scans_run_through_dispatch_and_live_targets_need_the_server_flag() {
        let (mut ctx, dir) = test_context();
        ctx.sig_packs =
            crate::sigpacks::SigPacksState::open_beside(&ctx.data_dir.join("rule-packs.sqlite3"));
        let templates = dir.path().join("tpl");
        std::fs::create_dir_all(&templates).unwrap();
        std::fs::write(
            templates.join("marker.yaml"),
            "id: dispatch-marker\ninfo:\n  name: Dispatch marker\n  severity: medium\nfile:\n  - extensions: [conf]\n    matchers:\n      - type: word\n        words: [\"OXAUDIT-FIXTURE-DISPATCH\"]\n",
        )
        .unwrap();
        std::fs::write(
            templates.join("http.yaml"),
            "id: dispatch-http\ninfo:\n  name: Dispatch http\n  severity: info\nhttp:\n  - path: [\"{{BaseURL}}/x\"]\n    matchers:\n      - type: status\n        status: [200]\n",
        )
        .unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("app.conf"), "x\nOXAUDIT-FIXTURE-DISPATCH\n").unwrap();

        let none = dispatch(
            &ctx,
            "scan_templates",
            serde_json::json!({"request": {"path": target.to_string_lossy()}}),
        )
        .await;
        assert!(
            none.unwrap_err()
                .as_str()
                .unwrap()
                .contains("No applicable templates"),
            "a scan without templates must fail, not report no matches"
        );

        let preview = dispatch(
            &ctx,
            "validate_signature_pack",
            serde_json::json!({"kind": "nuclei", "path": templates.to_string_lossy()}),
        )
        .await
        .unwrap();
        assert_eq!(preview["ruleCount"], 2);
        assert_eq!(preview["protocols"]["http"], 1);
        assert_eq!(preview["protocols"]["file"], 1);
        assert_eq!(preview["notEvaluatedCount"], 0);
        let installed = dispatch(
            &ctx,
            "install_signature_pack",
            serde_json::json!({"request": {
                "kind": "nuclei", "path": templates.to_string_lossy(),
                "name": "Dispatch", "license": "Apache-2.0"
            }}),
        )
        .await
        .unwrap();
        let id = installed["id"].as_str().unwrap().to_owned();

        let scan = dispatch(
            &ctx,
            "scan_templates",
            serde_json::json!({"request": {"path": target.to_string_lossy()}}),
        )
        .await
        .unwrap();
        assert_eq!(scan["state"], "completed");
        assert_eq!(scan["mode"], "path");
        assert_eq!(scan["matches"].as_array().unwrap().len(), 1);
        assert_eq!(
            scan["matches"][0]["ruleId"],
            format!("{id}/dispatch-marker")
        );
        assert_eq!(scan["matches"][0]["lines"][0]["line"], 2);
        assert_eq!(scan["notEvaluated"][0]["templateId"], "dispatch-http");
        assert_eq!(scan["requestsSent"], 0);

        // A loopback listener stands in for a live target; it counts every
        // connection so the refusal can be shown to send nothing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut socket, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let live_request = serde_json::json!({"request": {
            "targets": [format!("http://127.0.0.1:{port}")],
            "authorization": {"acknowledged": true, "statement": "my lab"}
        }});
        let runs_before = ctx.app.scan_work.snapshot().unwrap().recent.len();
        let refused = dispatch(&ctx, "scan_templates", live_request.clone()).await;
        assert_eq!(refused.unwrap_err().as_str().unwrap(), LIVE_TARGETS_REFUSED);
        assert!(LIVE_TARGETS_REFUSED.contains("--allow-live-targets"));
        // Refused before validation: even an unauthorised request gets the
        // server refusal, and nothing was started or sent.
        let unauthorised = dispatch(
            &ctx,
            "scan_templates",
            serde_json::json!({"request": {"targets": [format!("http://127.0.0.1:{port}")]}}),
        )
        .await;
        assert_eq!(
            unauthorised.unwrap_err().as_str().unwrap(),
            LIVE_TARGETS_REFUSED
        );
        assert_eq!(
            ctx.app.scan_work.snapshot().unwrap().recent.len(),
            runs_before,
            "the refusal starts no work"
        );
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the refusal sent nothing"
        );

        // With the flag the same request runs; the http template matches.
        ctx.allow_live_targets = true;
        ctx.app
            .settings
            .lock()
            .unwrap()
            .live_scan
            .requests_per_second = 1000;
        let live = dispatch(&ctx, "scan_templates", live_request)
            .await
            .unwrap();
        assert_eq!(live["mode"], "targets");
        assert_eq!(live["state"], "completed", "{live}");
        assert_eq!(live["authorization"]["acknowledged"], true);
        assert!(connections.load(std::sync::atomic::Ordering::SeqCst) > 0);
        let unauthorised = dispatch(
            &ctx,
            "scan_templates",
            serde_json::json!({"request": {"targets": [format!("http://127.0.0.1:{port}")]}}),
        )
        .await;
        assert!(unauthorised
            .unwrap_err()
            .as_str()
            .unwrap()
            .contains("explicit authorization"));
    }

    #[tokio::test]
    async fn todo_list_returns_empty_list_in_server_mode() {
        let (ctx, _dir) = test_context();
        let result = dispatch(
            &ctx,
            "todo_list",
            serde_json::json!({ "conversationId": "c1" }),
        )
        .await
        .expect("todo_list should succeed");
        assert_eq!(result, serde_json::json!([]));
    }

    #[tokio::test]
    async fn steer_chat_returns_false_when_no_run_is_active() {
        let (ctx, _dir) = test_context();
        let result = dispatch(
            &ctx,
            "steer_chat",
            serde_json::json!({ "runId": "run-1", "message": "keep going" }),
        )
        .await
        .expect("steer_chat should succeed");
        assert_eq!(result, serde_json::json!(false));
    }
}
