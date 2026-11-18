//! The Template scan command.
//!
//! Follows the YARA scan's lifecycle exactly: a work lease, a canonical run
//! with state transitions, run warnings for anything that narrows coverage, a
//! stored projection, and a terminal state that says what was and was not
//! evaluated. Zero matches means "no template matched"; it is never a
//! statement about the scanned content or target. Templates that were not
//! evaluated are always listed and counted but do not by themselves make a
//! run Incomplete, unless nothing at all was evaluated: templates were
//! selected but no file was evaluated by any of them (path scans) or no
//! request of any of them was answered (live scans). That run is Incomplete
//! with `template_nothing_evaluated`, never "no template matched".

use super::*;

use crate::sigpacks::SigPacksState;
use crate::template::{TemplateScanRequest, TemplateScanResult};

/// Scan a local path with `file` templates, or (when the live executor is
/// available) live targets with network templates.
///
/// Emits `template://progress` (throttled) and the usual `run://event`
/// stream; cancel it with `cancel_scan_work`.
#[tauri::command]
pub async fn scan_templates(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    sig_packs: State<'_, SigPacksState>,
    request: TemplateScanRequest,
) -> Result<TemplateScanResult, String> {
    struct TauriEvents(AppHandle);
    impl crate::findings::service::ScanEventSink for TauriEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let progress_app = app.clone();
    let progress: Arc<dyn Fn(Value) + Send + Sync> = Arc::new(move |payload| {
        let _ = progress_app.emit("template://progress", payload);
    });
    // A snapshot: a settings change during the scan does not change its limits.
    let live_settings = state
        .settings
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .live_scan
        .clone();
    scan_templates_engine(
        &state.scan_work,
        &findings,
        &sig_packs,
        &TauriEvents(app),
        progress,
        request,
        &live_settings,
    )
    .await
}

#[cfg(not(feature = "templates"))]
pub(crate) async fn scan_templates_engine(
    _scan_work: &crate::scan_work::ScanWorkRegistry,
    _findings: &FindingsState,
    _packs: &SigPacksState,
    _events: &dyn crate::findings::service::ScanEventSink,
    _progress: Arc<dyn Fn(Value) + Send + Sync>,
    _request: TemplateScanRequest,
    _live_settings: &crate::models::LiveScanSettings,
) -> Result<TemplateScanResult, String> {
    Err("This build of oxAudit has no template engine, so no scan was run. Install a build with the `templates` feature.".into())
}

#[cfg(feature = "templates")]
pub(crate) use engine::scan_templates_engine;

#[cfg(feature = "templates")]
mod engine {
    use oxaudit_domain::{RulePackId, RunKind, RunState};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::livenet::LiveProgress;
    use crate::sigpacks::{PackKind, ResolvedSigPacks};
    use crate::template::exec::Execution;
    use crate::template::files::{self, FileScanInput};
    use crate::template::live::{self, LiveInput};
    use crate::template::select::{self, Candidate, Filters, Selected};
    use crate::template::{
        graph, max_file_bytes, validate_request, NotEvaluatedRow, RecordedAuthorization, ScanMode,
        TemplatePackInfo, ADHOC_PACK_ID, MAX_MATCH_ROWS, MAX_NOT_EVALUATED_ROWS,
    };

    /// The durable receipt of a live scan's authorization: who was
    /// targeted, when the user confirmed, and what they said.
    fn authorization_receipt(targets: &[String], recorded: &RecordedAuthorization) -> String {
        let statement = recorded.statement.trim();
        format!(
            "Live-target scan started with the user's acknowledgement that they are authorized to test the targets (acknowledged at {} ms since the Unix epoch). Targets ({}): {}. Statement: {}",
            recorded.acknowledged_at_ms,
            targets.len(),
            targets.join(", "),
            if statement.is_empty() {
                "(none given)"
            } else {
                statement
            }
        )
    }

    fn stage(
        managed: &mut Option<oxaudit_application::ManagedRun<'_>>,
        state: RunState,
    ) -> Result<(), String> {
        managed
            .as_mut()
            .expect("template run exists")
            .transition(state, epoch_millis())
            .map_err(|error| error.to_string())
    }

    fn warn(
        managed: &mut Option<oxaudit_application::ManagedRun<'_>>,
        code: &str,
        message: impl Into<String>,
    ) {
        if let Some(run) = managed.as_mut() {
            run.warning(code, message);
        }
    }

    /// Templates supplied for this scan only, loaded.
    struct Adhoc {
        files: Vec<crate::sigpacks::PackFile>,
        /// `(file, message)` for files that could not even be read as text.
        unread: Vec<(String, String)>,
        sha256: String,
        sources: Vec<String>,
    }

    fn collect_adhoc(paths: &[String]) -> Result<Option<Adhoc>, String> {
        if paths.is_empty() {
            return Ok(None);
        }
        let mut files = Vec::new();
        let mut unread = Vec::new();
        let mut sources = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let collected = crate::sigpacks::collect_source(PackKind::Nuclei, Path::new(path))
                .map_err(|error| format!("templates {path}: {error}"))?;
            let prefix = format!("extra{}", index + 1);
            sources.push(format!("{prefix} = {path}"));
            for skip in collected.skipped {
                unread.push((format!("{prefix}/{}", skip.file), skip.message));
            }
            for file in collected.files {
                files.push(crate::sigpacks::PackFile {
                    path: format!("{prefix}/{}", file.path),
                    text: file.text,
                });
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut hasher = Sha256::new();
        for file in &files {
            hasher.update(
                format!(
                    "{}  {}\n",
                    hex::encode(Sha256::digest(file.text.as_bytes())),
                    file.path
                )
                .as_bytes(),
            );
        }
        Ok(Some(Adhoc {
            files,
            unread,
            sha256: hex::encode(hasher.finalize()),
            sources,
        }))
    }

    /// A row for a file that did not load as a template (or repeated an id).
    fn file_row(pack: &str, file: &str, reason: String) -> NotEvaluatedRow {
        NotEvaluatedRow {
            template_id: String::new(),
            pack: pack.to_owned(),
            file: file.to_owned(),
            protocol: None,
            target: None,
            reason,
        }
    }

    /// Load one pack's (or the one-off files') templates into `candidates`;
    /// returns how many are supported. Files that do not load, and repeated
    /// ids, become not-evaluated rows.
    fn load_group(
        candidates: &mut Vec<Candidate>,
        file_rows: &mut Vec<NotEvaluatedRow>,
        pack: &str,
        files: &[crate::sigpacks::PackFile],
    ) -> usize {
        let loaded = crate::sigpacks::load_templates(files);
        let mut supported = 0usize;
        for (file, message) in loaded.errors {
            file_rows.push(file_row(pack, &file, format!("did not load: {message}")));
        }
        for (file, id, first) in loaded.duplicates {
            file_rows.push(file_row(
                pack,
                &file,
                format!("duplicate template id `{id}`; the copy in {first} is used"),
            ));
        }
        for entry in loaded.templates {
            if entry.template.is_supported() {
                supported += 1;
            }
            candidates.push(Candidate {
                pack: pack.to_owned(),
                file: entry.file,
                template: entry.template,
            });
        }
        supported
    }

    fn zero_templates_error(
        mode: ScanMode,
        resolved_skipped: &[(String, String)],
        store_error: Option<&str>,
        loaded: usize,
        exclusions: select::Exclusions,
        not_evaluated: &[NotEvaluatedRow],
        had_sources: bool,
    ) -> String {
        let mut message = String::from(
            "No applicable templates are available to scan with, so no scan was run (a scan with no templates cannot report \"no template matched\").",
        );
        if !had_sources {
            if resolved_skipped.is_empty() {
                message.push_str(
                    " No enabled Nuclei pack is installed and no one-off template files were given; import a pack or pass template files.",
                );
            } else {
                message.push_str(
                    " Enabled Nuclei pack(s) are installed, but every one failed verification and was not applied, and no one-off template files were given.",
                );
            }
        } else if loaded == 0 {
            message.push_str(" Template files were found, but none of them loaded as a template.");
        } else {
            let kind = match mode {
                ScanMode::Path => "file-protocol templates for a local path scan",
                ScanMode::Targets => "network templates for a live-target scan",
            };
            let mut causes: Vec<String> = Vec::new();
            let mut cause = |count: usize, text: &str| {
                if count > 0 {
                    causes.push(format!("{count} {text}"));
                }
            };
            cause(
                exclusions.filtered,
                "left out by the tag, severity or id filters you gave",
            );
            cause(exclusions.dos, "tagged `dos`, which never run");
            cause(
                exclusions.intrusive,
                "tagged `intrusive` or `fuzz`, which need the intrusive switch",
            );
            cause(
                exclusions.unsupported,
                "use features this engine does not evaluate",
            );
            cause(exclusions.wrong_mode, &format!("are not {kind}"));
            message.push_str(&format!(
                " {loaded} template(s) were loaded, but none can run: {}.",
                causes.join("; ")
            ));
        }
        if let Some(error) = store_error {
            message.push_str(&format!(
                " The signature-pack store is unavailable: {error}."
            ));
        }
        for (id, reason) in resolved_skipped.iter().take(5) {
            message.push_str(&format!(" Pack {id} was not applied: {reason}."));
        }
        if let Some(first) = not_evaluated.first() {
            message.push_str(&format!(
                " {} template(s) were not evaluated; first: {}/{}: {}.",
                not_evaluated.len(),
                first.pack,
                if first.template_id.is_empty() {
                    first.file.as_str()
                } else {
                    first.template_id.as_str()
                },
                first.reason
            ));
        }
        message
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn scan_templates_engine(
        scan_work: &crate::scan_work::ScanWorkRegistry,
        findings: &FindingsState,
        packs: &SigPacksState,
        events: &dyn crate::findings::service::ScanEventSink,
        progress: Arc<dyn Fn(Value) + Send + Sync>,
        request: TemplateScanRequest,
        live_settings: &crate::models::LiveScanSettings,
    ) -> Result<TemplateScanResult, String> {
        let mode = validate_request(&request)?;
        let max_bytes = max_file_bytes(&request);
        // Live scans: parse the scope and build the limits before any work
        // or run exists, so a bad target or unusable settings are request
        // errors and nothing is sent. The acknowledgement (validated above)
        // is recorded with this run only and never stored in settings.
        let (mut live_plan, recorded_authorization) = match mode {
            ScanMode::Path => (None, None),
            ScanMode::Targets => {
                let plan = live::plan(&request.targets, live_settings, request.rate_limit)?;
                let authorization = request.authorization.clone().unwrap_or_default();
                (
                    Some(plan),
                    Some(RecordedAuthorization {
                        acknowledged: authorization.acknowledged,
                        statement: authorization.statement,
                        acknowledged_at_ms: epoch_millis(),
                    }),
                )
            }
        };
        let started = std::time::Instant::now();
        let label = match mode {
            ScanMode::Path => request.path.clone().unwrap_or_default(),
            ScanMode::Targets => request.targets.join(", "),
        };
        let mut work = scan_work.begin(
            crate::scan_work::WorkKind::Template,
            &label,
            request.operation_id.as_deref(),
            events,
        )?;
        let cancel = work.cancellation();
        let operation_id = work.id().to_owned();

        let target_text = match mode {
            ScanMode::Path => Path::new(request.path.as_deref().unwrap_or_default())
                .canonicalize()
                .map_err(|error| format!("cannot resolve the template scan target: {error}"))?
                .to_string_lossy()
                .into_owned(),
            ScanMode::Targets => label.clone(),
        };
        // Reading template files and re-verifying packs is file I/O and
        // hashing: it runs on a blocking thread, never on a runtime worker.
        let adhoc_paths = request.extra_template_paths.clone();
        let adhoc = tokio::task::spawn_blocking(move || collect_adhoc(&adhoc_paths))
            .await
            .map_err(|error| format!("reading the template files did not finish: {error}"))??;

        // Installed packs, re-verified against their manifests. A pack that
        // fails is reported and makes the run Incomplete; it never silently
        // narrows the template set.
        let mut store_error: Option<String> = None;
        let resolved = match (packs.shared(), request.pack_ids.as_deref()) {
            (_, Some([])) => ResolvedSigPacks::default(),
            (Ok(store), ids) => {
                let (store, ids) = (store.clone(), ids.map(<[String]>::to_vec));
                tokio::task::spawn_blocking(move || store.resolve(PackKind::Nuclei, ids.as_deref()))
                    .await
                    .map_err(|error| {
                        format!("verifying the installed packs did not finish: {error}")
                    })??
            }
            (Err(error), Some(ids)) if !ids.is_empty() => return Err(error),
            (Err(error), _) => {
                store_error = Some(error);
                ResolvedSigPacks::default()
            }
        };

        let service = findings.service().map_err(|error| error.to_string())?;
        let canonical_repository =
            crate::adapters::persistence::CanonicalSqliteRepository::new(service.repository());
        let canonical_events = crate::presentation::CanonicalRunEvents::new(&work);
        let coordinator =
            oxaudit_application::RunCoordinator::new(&canonical_repository, &canonical_events);
        let mut run = oxaudit_domain::Run::queued(RunKind::Template, &target_text, epoch_millis());
        run.engine_ids = vec![format!("oxaudit-nuclei/{}", oxaudit_nuclei::VERSION)];
        run.rule_pack_ids = resolved
            .packs
            .iter()
            .map(|pack| {
                RulePackId::parse(format!(
                    "nuclei:{}@{}",
                    pack.record.id,
                    &pack.record.content_sha256[..12]
                ))
                .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()?;
        let mut managed = Some(coordinator.begin(run).map_err(|error| error.to_string())?);
        work.bind_run(
            managed
                .as_ref()
                .expect("template run exists")
                .run()
                .id
                .as_str(),
        );
        stage(&mut managed, RunState::Discovering)?;
        if let Some(recorded) = &recorded_authorization {
            warn(
                &mut managed,
                "live_scan_authorization",
                authorization_receipt(&request.targets, recorded),
            );
        }

        let pack_input: Vec<(
            crate::sigpacks::InstalledSigPack,
            Vec<crate::sigpacks::PackFile>,
        )> = resolved
            .packs
            .into_iter()
            .map(|pack| (pack.record, pack.files))
            .collect();
        let resolved_skipped = resolved.skipped;
        let mut incomplete_reasons: Vec<String> = Vec::new();
        for (id, reason) in &resolved_skipped {
            let message = format!("Pack {id} was not applied: {reason}");
            warn(&mut managed, "template_pack_skipped", message.clone());
            incomplete_reasons.push(message);
        }
        if let Some(error) = &store_error {
            let message = format!(
                "The signature-pack store is unavailable, so installed packs were not applied: {error}"
            );
            warn(
                &mut managed,
                "template_pack_store_unavailable",
                message.clone(),
            );
            incomplete_reasons.push(message);
        }
        if let Some(adhoc) = &adhoc {
            warn(
                &mut managed,
                "template_adhoc_templates",
                format!(
                    "One-off template files were applied (content sha256 {}): {}",
                    adhoc.sha256,
                    adhoc.sources.join("; ")
                ),
            );
        }

        let outcome: Result<TemplateScanResult, String> = async {
            // ---- templates (parsing is CPU work: a blocking thread)
            let (infos, mut candidates, file_rows, had_sources) =
                tokio::task::spawn_blocking(move || {
                    let mut infos: Vec<TemplatePackInfo> = Vec::new();
                    let mut candidates: Vec<Candidate> = Vec::new();
                    let mut file_rows: Vec<NotEvaluatedRow> = Vec::new();
                    let mut had_sources = false;
                    for (record, files) in &pack_input {
                        had_sources |= !files.is_empty();
                        let template_count =
                            load_group(&mut candidates, &mut file_rows, &record.id, files);
                        infos.push(TemplatePackInfo {
                            id: record.id.clone(),
                            name: record.name.clone(),
                            license: record.license.clone(),
                            content_sha256: record.content_sha256.clone(),
                            template_count,
                        });
                    }
                    if let Some(adhoc) = &adhoc {
                        had_sources |= !adhoc.files.is_empty();
                        for (file, message) in &adhoc.unread {
                            file_rows.push(file_row(
                                ADHOC_PACK_ID,
                                file,
                                format!("not read: {message}"),
                            ));
                        }
                        let template_count = load_group(
                            &mut candidates,
                            &mut file_rows,
                            ADHOC_PACK_ID,
                            &adhoc.files,
                        );
                        infos.push(TemplatePackInfo {
                            id: ADHOC_PACK_ID.into(),
                            name: "One-off template files".into(),
                            license: "not recorded (templates supplied for this scan only)".into(),
                            content_sha256: adhoc.sha256.clone(),
                            template_count,
                        });
                    }
                    (infos, candidates, file_rows, had_sources)
                })
                .await
                .map_err(|error| format!("loading the templates did not finish: {error}"))?;
            if cancel.load(Ordering::SeqCst) {
                return Err("Template scan cancelled".into());
            }
            let templates_loaded = candidates.len();
            candidates.sort_by(|a, b| {
                (&a.pack, &a.file, &a.template.id).cmp(&(&b.pack, &b.file, &b.template.id))
            });

            // ---- selection (shared by both modes)
            let selection = select::select(candidates, &Filters::from_request(&request), mode);
            let selected: Vec<Selected> = selection.selected;
            let exclusions = selection.exclusions;
            let mut not_evaluated: Vec<NotEvaluatedRow> = file_rows;
            not_evaluated.extend(selection.not_evaluated);
            if selected.is_empty() {
                return Err(zero_templates_error(
                    mode,
                    &resolved_skipped,
                    store_error.as_deref(),
                    templates_loaded,
                    exclusions,
                    &not_evaluated,
                    had_sources,
                ));
            }
            if cancel.load(Ordering::SeqCst) {
                return Err("Template scan cancelled".into());
            }
            stage(&mut managed, RunState::Detecting)?;

            // ---- execute
            let templates_run = selected.len();
            let executed: Execution = match mode {
                ScanMode::Path => {
                    let input = FileScanInput {
                        target: PathBuf::from(&target_text),
                        templates: selected.clone(),
                        max_file_bytes: max_bytes,
                    };
                    let scan_cancel = cancel.clone();
                    let scan_progress = progress.clone();
                    let scan_operation = operation_id.clone();
                    tokio::task::spawn_blocking(move || {
                        files::scan_path(&input, &scan_cancel, &move |done, total, bytes| {
                            scan_progress(json!({
                                "operationId": scan_operation,
                                "message": format!("Scanned {done} of {total} files"),
                                "done": done,
                                "total": total,
                                "bytesScanned": bytes,
                            }));
                        })
                    })
                    .await
                    .map_err(|error| format!("the scan did not finish: {error}"))??
                }
                ScanMode::Targets => {
                    let scan_progress = progress.clone();
                    let scan_operation = operation_id.clone();
                    live::run_live_targets(LiveInput {
                        plan: live_plan
                            .take()
                            .ok_or("the live scan was not planned before it started")?,
                        templates: selected.clone(),
                        cancel: cancel.clone(),
                        progress: Arc::new(move |p: LiveProgress| {
                            scan_progress(json!({
                                "operationId": scan_operation,
                                "message": format!(
                                    "Completed {} of {} template-target checks; {} request(s) sent, {} match(es)",
                                    p.pairs_done, p.pairs_total, p.requests_sent, p.matches
                                ),
                                "done": p.pairs_done,
                                "total": p.pairs_total,
                                "requestsSent": p.requests_sent,
                                "matches": p.matches,
                            }));
                        }),
                    })
                    .await?
                }
            };
            if cancel.load(Ordering::SeqCst) || executed.cancelled {
                return Err("Template scan cancelled".into());
            }
            stage(&mut managed, RunState::Normalizing)?;

            // ---- graph
            let run_id = managed
                .as_ref()
                .expect("template run exists")
                .run()
                .id
                .clone();
            let built = graph::build(&run_id, &selected, &executed.matches, oxaudit_nuclei::VERSION)?;
            if !built.artifacts.is_empty() {
                managed
                    .as_mut()
                    .expect("template run exists")
                    .append_artifacts(&built.artifacts)
                    .map_err(|error| error.to_string())?;
            }
            if !built.observations.is_empty() {
                managed
                    .as_mut()
                    .expect("template run exists")
                    .append_observations(built.observations)
                    .map_err(|error| error.to_string())?;
            }
            stage(&mut managed, RunState::Assessing)?;

            for (code, message) in &executed.incomplete {
                warn(&mut managed, code, message.clone());
                incomplete_reasons.push(message.clone());
            }
            if executed.evaluated == 0 {
                let message = match mode {
                    ScanMode::Path => format!(
                        "{templates_run} template(s) were selected, but no file in the target was evaluated by any of them (no file was found, none matched a selected template's file rules, or every applicable file was skipped), so none could be evaluated and the absence of matches means nothing."
                    ),
                    ScanMode::Targets => format!(
                        "{templates_run} template(s) were selected against {} target(s), but no request of any template was answered, so none could be evaluated and the absence of matches means nothing.",
                        request.targets.len()
                    ),
                };
                warn(&mut managed, "template_nothing_evaluated", message.clone());
                incomplete_reasons.push(message);
            }
            if built.dropped > 0 {
                let message = format!(
                    "More than {MAX_MATCH_ROWS} template matches were found; {} were counted but not stored.",
                    built.dropped
                );
                warn(&mut managed, "template_match_cap", message.clone());
                incomplete_reasons.push(message);
            }
            not_evaluated.extend(executed.not_evaluated);
            let not_evaluated_total = not_evaluated.len();
            let not_evaluated_dropped = not_evaluated_total.saturating_sub(MAX_NOT_EVALUATED_ROWS);
            not_evaluated.truncate(MAX_NOT_EVALUATED_ROWS);
            let mut notes: Vec<String> = Vec::new();
            if not_evaluated_total > 0 {
                let message = format!(
                    "{not_evaluated_total} template(s) or template checks were not evaluated; each is listed with its reason."
                );
                warn(&mut managed, "template_not_evaluated", message.clone());
                notes.push(message);
            }
            if not_evaluated_dropped > 0 {
                notes.push(format!(
                    "{not_evaluated_dropped} more not-evaluated rows were counted but not listed."
                ));
            }
            let mut skipped = executed.skipped;
            if skipped.dropped > 0 {
                notes.push(format!(
                    "{} more skipped files were counted but not listed.",
                    skipped.dropped
                ));
            }
            notes.extend(executed.notes);
            let incomplete = !incomplete_reasons.is_empty();
            notes.extend(incomplete_reasons.iter().cloned());

            let result = TemplateScanResult {
                run_id: run_id.to_string(),
                mode: mode.as_str().into(),
                target: target_text.clone(),
                state: if incomplete { "incomplete" } else { "completed" }.into(),
                matches: built.rows,
                matches_dropped: built.dropped,
                not_evaluated,
                not_evaluated_dropped: not_evaluated_dropped as u64,
                packs: infos,
                templates_loaded,
                templates_run,
                files_scanned: executed.files_scanned,
                bytes_scanned: executed.bytes_scanned,
                skipped: std::mem::take(&mut skipped.rows),
                requests_sent: executed.requests_sent,
                requests_refused: executed.requests_refused,
                refused_hosts: executed.refused_hosts,
                resolved: executed.resolved,
                unreachable_targets: executed.unreachable,
                authorization: recorded_authorization.clone(),
                notes,
                incomplete_reasons,
                duration_ms: started.elapsed().as_millis() as u64,
            };
            stage(&mut managed, RunState::Persisting)?;
            service
                .repository()
                .canonical_save_projection(&run_id, "template", 1, &result)
                .map_err(|error| error.to_string())?;
            if cancel.load(Ordering::SeqCst) {
                return Err("Template scan cancelled".into());
            }
            if incomplete {
                managed
                    .take()
                    .expect("template run exists")
                    .terminate(RunState::Incomplete, epoch_millis())
                    .map_err(|error| error.to_string())?;
            } else {
                managed
                    .as_mut()
                    .expect("template run exists")
                    .complete_in_place(epoch_millis())
                    .map_err(|error| error.to_string())?;
            }
            Ok(result)
        }
        .await;

        let cancelled = cancel.load(Ordering::SeqCst);
        let run_id = managed.as_ref().map(|run| run.run().id.to_string());
        let terminal_error = match &outcome {
            Err(error) => {
                if let Some(mut run) = managed.take() {
                    let terminal = if cancelled || error.contains("cancelled") {
                        RunState::Cancelled
                    } else {
                        run.warning("template_failed", error.clone());
                        RunState::Failed
                    };
                    run.terminate(terminal, epoch_millis())
                        .err()
                        .map(|persist| {
                            format!("{error}; could not save terminal run state: {persist}")
                        })
                } else {
                    None
                }
            }
            Ok(_) => None,
        };
        drop(managed);
        match &outcome {
            Ok(result) => work.finish(&result.state, Some(&result.run_id)),
            Err(_) => work.finish(
                if cancelled { "cancelled" } else { "failed" },
                run_id.as_deref(),
            ),
        }
        match (outcome, terminal_error) {
            (Err(_), Some(error)) => Err(error),
            (outcome, _) => outcome,
        }
    }
}

#[cfg(all(test, feature = "templates"))]
mod tests {
    use super::*;
    use crate::findings::repository::FindingsRepository;
    use crate::findings::service::FindingsService;
    use crate::sigpacks::{PackKind, PackMetadata, SigPackStore};
    use oxaudit_domain::{ObservationKind, RunId, RunState};

    const WORD: &str = r#"id: fixture-marker-word
info:
  name: Fixture marker word
  author: oxaudit-tests
  severity: high
  description: Finds the fixture marker.
  tags: fixture,marker
  classification:
    cwe-id: CWE-200
file:
  - extensions:
      - conf
    matchers:
      - type: word
        name: marker
        words:
          - "OXAUDIT-FIXTURE-MARKER"
"#;
    const VERSION: &str = r#"id: fixture-version-regex
info:
  name: Fixture version regex
  author: oxaudit-tests
  severity: low
  tags: fixture
file:
  - extensions:
      - conf
      - ini
    matchers:
      - type: regex
        regex:
          - 'version\s*=\s*\d+\.\d+'
    extractors:
      - type: regex
        name: ver
        group: 1
        regex:
          - 'version\s*=\s*(\d+\.\d+)'
"#;
    const SECRET: &str = r#"id: fixture-token
info:
  name: Fixture token
  author: oxaudit-tests
  severity: critical
  tags: token,exposure
file:
  - extensions:
      - env
    matchers:
      - type: regex
        regex:
          - 'FIXTURE_TOKEN=[A-Za-z0-9]{20,}'
    extractors:
      - type: regex
        name: value
        group: 1
        regex:
          - 'FIXTURE_TOKEN=([A-Za-z0-9]{20,})'
"#;
    const DOS: &str = r#"id: fixture-dos
info:
  name: Fixture dos
  author: oxaudit-tests
  severity: high
  tags: dos,fixture
file:
  - extensions: [all]
    matchers:
      - type: word
        words: ["DOS-FIXTURE-MARKER"]
"#;
    const INTRUSIVE: &str = r#"id: fixture-intrusive
info:
  name: Fixture intrusive
  author: oxaudit-tests
  severity: medium
  tags: intrusive
file:
  - extensions: [all]
    matchers:
      - type: word
        words: ["INTRUSIVE-FIXTURE-MARKER"]
"#;
    const HTTP_ONLY: &str = r#"id: fixture-http-only
info:
  name: Fixture http only
  author: oxaudit-tests
  severity: info
  tags: fixture
http:
  - method: GET
    path:
      - "{{BaseURL}}/fixture"
    matchers:
      - type: status
        status:
          - 200
"#;
    const HEADLESS: &str = r#"id: fixture-headless
info:
  name: Fixture headless
  author: oxaudit-tests
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}"
"#;
    const ARCHIVE: &str = r#"id: fixture-archive
info:
  name: Fixture archive
  author: oxaudit-tests
  severity: info
file:
  - extensions: [all]
    archive: true
    matchers:
      - type: word
        words: ["ARCHIVE-FIXTURE-MARKER"]
"#;
    const NEEDLE_SMALL: &str = r#"id: fixture-needle-small
info:
  name: Fixture needle small
  author: oxaudit-tests
  severity: info
file:
  - extensions: [all]
    denylist: [bak]
    max-size: 20b
    matchers:
      - type: word
        words: ["needle"]
"#;
    const NEEDLE_ROOT: &str = r#"id: fixture-needle-root
info:
  name: Fixture needle root
  author: oxaudit-tests
  severity: info
file:
  - extensions: [all]
    no-recursive: true
    matchers:
      - type: word
        words: ["needle"]
"#;

    struct Quiet;
    impl crate::findings::service::ScanEventSink for Quiet {
        fn emit(&self, _event: &str, _payload: Value) -> Result<(), CommandError> {
            Ok(())
        }
    }

    struct Harness {
        state: Arc<AppState>,
        findings: FindingsState,
        packs: SigPacksState,
        dir: tempfile::TempDir,
    }

    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = SigPackStore::open(&dir.path().join("data/rule-packs.sqlite3")).unwrap();
            Self {
                state: Arc::new(AppState::new()),
                findings: FindingsState::available(FindingsService::new(
                    FindingsRepository::open_in_memory().unwrap(),
                )),
                packs: SigPacksState::available(store),
                dir,
            }
        }

        fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
            let path = self.dir.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            path
        }

        /// A folder of templates under `tpl/` and a request scanning
        /// `target/` with only those (no installed packs).
        fn adhoc(&self, templates: &[(&str, &str)]) -> TemplateScanRequest {
            for (name, text) in templates {
                self.write(&format!("tpl/{name}.yaml"), text);
            }
            TemplateScanRequest {
                path: Some(
                    self.dir
                        .path()
                        .join("target")
                        .to_string_lossy()
                        .into_owned(),
                ),
                pack_ids: Some(vec![]),
                extra_template_paths: vec![self
                    .dir
                    .path()
                    .join("tpl")
                    .to_string_lossy()
                    .into_owned()],
                ..Default::default()
            }
        }

        fn install(&self, name: &str, dir: &str) -> crate::sigpacks::InstalledSigPack {
            self.packs
                .store()
                .unwrap()
                .install(
                    PackKind::Nuclei,
                    &self.dir.path().join(dir),
                    &PackMetadata {
                        name: name.into(),
                        license: "Apache-2.0".into(),
                        ..Default::default()
                    },
                    "2026-11-18T00:00:00Z",
                )
                .unwrap()
        }

        async fn scan(&self, request: TemplateScanRequest) -> Result<TemplateScanResult, String> {
            self.scan_with(request, Arc::new(|_| {})).await
        }

        async fn scan_with(
            &self,
            request: TemplateScanRequest,
            progress: Arc<dyn Fn(Value) + Send + Sync>,
        ) -> Result<TemplateScanResult, String> {
            self.scan_live(request, &fast_live(), progress).await
        }

        async fn scan_live(
            &self,
            request: TemplateScanRequest,
            live: &crate::models::LiveScanSettings,
            progress: Arc<dyn Fn(Value) + Send + Sync>,
        ) -> Result<TemplateScanResult, String> {
            scan_templates_engine(
                &self.state.scan_work,
                &self.findings,
                &self.packs,
                &Quiet,
                progress,
                request,
                live,
            )
            .await
        }

        fn repository(&self) -> &FindingsRepository {
            self.findings.service().unwrap().repository()
        }

        fn run_state(&self, run_id: &str) -> RunState {
            self.repository()
                .canonical_load_run(&RunId::parse(run_id).unwrap())
                .unwrap()
                .expect("run is stored")
                .state
        }
    }

    fn ids(result: &TemplateScanResult) -> Vec<String> {
        result
            .matches
            .iter()
            .map(|m| m.template_id.clone())
            .collect()
    }

    #[tokio::test]
    async fn a_path_scan_that_evaluates_no_file_is_incomplete_not_completed() {
        let h = Harness::new();
        // The only template reads .conf files; the target holds none.
        h.write("target/readme.txt", "OXAUDIT-FIXTURE-MARKER");
        let req = h.adhoc(&[("version", VERSION)]);
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.files_scanned, 0);
        assert_eq!(result.state, "incomplete", "{:?}", result.notes);
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|r| r.contains("1 template(s) were selected")
                && r.contains("no file in the target was evaluated")));
        let run = h.run_state(&result.run_id);
        assert_eq!(run, RunState::Incomplete);

        // An empty folder is the same.
        std::fs::remove_file(h.dir.path().join("target/readme.txt")).unwrap();
        let req = h.adhoc(&[("version", VERSION)]);
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.state, "incomplete");
    }

    #[tokio::test]
    async fn word_and_regex_templates_match_with_lines_and_a_canonical_graph() {
        let h = Harness::new();
        h.write(
            "target/a/app.conf",
            "alpha\nbeta OXAUDIT-FIXTURE-MARKER here\nversion = 4.12\n",
        );
        h.write("target/b.txt", "OXAUDIT-FIXTURE-MARKER");
        h.write("target/c.conf", "nothing to see here");
        let req = h.adhoc(&[("marker", WORD), ("version", VERSION)]);
        let result = h.scan(req).await.unwrap();

        assert_eq!(result.state, "completed", "{:?}", result.notes);
        assert_eq!(result.mode, "path");
        assert_eq!(result.templates_loaded, 2);
        assert_eq!(result.templates_run, 2);
        assert_eq!(result.files_scanned, 2, "only the .conf files were read");
        assert_eq!(result.requests_sent, 0);
        assert!(result.authorization.is_none());
        assert!(result.not_evaluated.is_empty());
        assert_eq!(
            ids(&result),
            ["fixture-marker-word", "fixture-version-regex"]
        );
        assert!(result
            .notes
            .iter()
            .any(|n| n.contains("1 file(s) were not read")));

        let word = &result.matches[0];
        assert_eq!(word.id, "match-1");
        assert_eq!(word.rule_id, "adhoc/fixture-marker-word");
        assert_eq!(word.pack, "adhoc");
        assert_eq!(word.severity, "high");
        assert_eq!(word.protocol, "file");
        assert_eq!(word.file_path.as_deref(), Some("a/app.conf"));
        assert!(word.matched_at.ends_with("a/app.conf"));
        assert_eq!(word.tags, ["fixture", "marker"]);
        assert_eq!(word.matcher_names, ["marker"]);
        assert_eq!(word.classification.cwe_id, ["CWE-200"]);
        assert_eq!(word.description, "Finds the fixture marker.");
        assert!(word.exchange.is_none());
        assert_eq!(word.lines.len(), 1);
        assert_eq!(word.lines[0].line, 2);
        assert_eq!(word.lines[0].start_column, 6);
        assert_eq!(word.lines[0].end_column, 6 + 22);
        assert_eq!(word.lines[0].text, "beta OXAUDIT-FIXTURE-MARKER here");

        let version = &result.matches[1];
        assert_eq!(version.lines[0].line, 3);
        assert_eq!(version.lines[0].start_column, 1);
        assert_eq!(
            version.extracted,
            vec![("ver".to_string(), vec!["4.12".to_string()])],
            "a template that does not report credentials keeps its extracted values"
        );

        // The run, projection and graph were stored.
        let run_id = RunId::parse(result.run_id.clone()).unwrap();
        assert_eq!(h.run_state(&result.run_id), RunState::Completed);
        let projection = h
            .repository()
            .canonical_load_projection(&run_id)
            .unwrap()
            .expect("projection is stored");
        assert_eq!(projection["matches"].as_array().unwrap().len(), 2);
        assert_eq!(projection["requestsRefused"], 0);
        assert!(projection["authorization"].is_null());
        assert!(projection["matches"][0]["exchange"].is_null());
        let (artifacts, _, observations) =
            h.repository().canonical_load_report_graph(&run_id).unwrap();
        assert_eq!(artifacts.len(), 1, "one artifact per matched file");
        assert_eq!(artifacts[0].location.normalized_path, "a/app.conf");
        assert_eq!(observations.len(), 2);
        let record = observations
            .iter()
            .find(|r| r.observation.rule_id.as_deref() == Some("adhoc/fixture-marker-word"))
            .expect("the word match is in the graph");
        let observation = &record.observation;
        assert_eq!(observation.kind, ObservationKind::TemplateMatch);
        assert_eq!(observation.detector_id, "oxaudit-nuclei");
        assert_eq!(observation.detector_version, oxaudit_nuclei::VERSION);
        assert_eq!(
            observation.rule_id.as_deref(),
            Some("adhoc/fixture-marker-word")
        );
        match &record.evidence[0].evidence {
            oxaudit_domain::Evidence::FileLocation(location) => {
                assert_eq!(location.normalized_path, "a/app.conf");
                assert_eq!(location.start_line, Some(2));
                assert_eq!(location.start_column, Some(6));
                assert_eq!(location.end_column, Some(28));
            }
            other => panic!("unexpected evidence {other:?}"),
        }

        // Both paged sections the registry declares are readable.
        let page = h
            .repository()
            .canonical_projection_page(&run_id, "matches", &Default::default())
            .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.items[0]["ruleId"], "adhoc/fixture-marker-word");
        let high = h
            .repository()
            .canonical_projection_page(
                &run_id,
                "matches",
                &crate::findings::domain::ResultPageQuery {
                    severity: Some("high".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(high.filtered_total, 1, "the severity key is indexed");
        let by_file = h
            .repository()
            .canonical_projection_page(
                &run_id,
                "matches",
                &crate::findings::domain::ResultPageQuery {
                    search: "a/app.conf".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(by_file.filtered_total, 2);
        assert!(h
            .repository()
            .canonical_projection_page(&run_id, "notEvaluated", &Default::default())
            .is_ok());
    }

    #[tokio::test]
    async fn extension_denylist_max_size_and_no_recursive_rules_are_applied() {
        let h = Harness::new();
        h.write("target/ok.cfg", "needle");
        h.write("target/old.bak", "needle");
        h.write("target/notes.txt", "needle");
        h.write("target/big.cfg", format!("needle{}", "x".repeat(100)));
        h.write("target/sub/deep.cfg", "needle");
        let req = h.adhoc(&[("small", NEEDLE_SMALL), ("root", NEEDLE_ROOT)]);
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.state, "completed");
        let mut hits: Vec<(String, String)> = result
            .matches
            .iter()
            .map(|m| (m.template_id.clone(), m.file_path.clone().unwrap()))
            .collect();
        hits.sort();
        assert_eq!(
            hits,
            [
                // `root` is no-recursive: only files directly in the target.
                // It keeps the default 5 MiB max-size, so it reads big.cfg.
                ("fixture-needle-root".to_string(), "big.cfg".to_string()),
                ("fixture-needle-root".to_string(), "ok.cfg".to_string()),
                ("fixture-needle-root".to_string(), "old.bak".to_string()),
                // `small` denies .bak and .txt (default denylist), has a
                // 20 byte max-size, and recurses.
                ("fixture-needle-small".to_string(), "ok.cfg".to_string()),
                (
                    "fixture-needle-small".to_string(),
                    "sub/deep.cfg".to_string()
                ),
            ]
        );
        assert!(
            result
                .matches
                .iter()
                .all(|m| m.file_path.as_deref() != Some("notes.txt")),
            "the default denylist drops .txt for both templates"
        );
    }

    #[tokio::test]
    async fn max_size_alone_keeps_a_file_unread_and_counted() {
        let h = Harness::new();
        h.write("target/big.cfg", format!("needle{}", "x".repeat(100)));
        h.write("target/ok.cfg", "needle");
        let req = h.adhoc(&[("small", NEEDLE_SMALL)]);
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.matches.len(), 1);
        assert!(result
            .notes
            .iter()
            .any(|n| n.contains("exceed the max-size")));
    }

    #[tokio::test]
    async fn tag_severity_and_id_filters_select_templates_without_listing_the_rest() {
        let h = Harness::new();
        h.write("target/app.conf", "OXAUDIT-FIXTURE-MARKER\nversion = 1.0\n");
        h.write("target/app.env", "FIXTURE_TOKEN=Zx9Qw3Lm7Rt2Vb5Nc8Kd\n");
        let base = h.adhoc(&[("marker", WORD), ("version", VERSION), ("secret", SECRET)]);

        let run = |edit: &dyn Fn(&mut TemplateScanRequest)| {
            let mut req = base.clone_for_test();
            edit(&mut req);
            req
        };
        let result = h
            .scan(run(&|r| r.tags = vec!["marker".into()]))
            .await
            .unwrap();
        assert_eq!(ids(&result), ["fixture-marker-word"]);
        assert_eq!(result.templates_run, 1);
        assert_eq!(result.templates_loaded, 3);
        assert!(
            result.not_evaluated.is_empty(),
            "filtered out is not listed"
        );

        // Tags are any-of, and a comma list is accepted.
        let result = h
            .scan(run(&|r| r.tags = vec!["marker,token".into()]))
            .await
            .unwrap();
        assert_eq!(ids(&result), ["fixture-marker-word", "fixture-token"]);

        let result = h
            .scan(run(&|r| r.exclude_tags = vec!["fixture".into()]))
            .await
            .unwrap();
        assert_eq!(ids(&result), ["fixture-token"]);

        let result = h
            .scan(run(&|r| r.severities = vec!["LOW".into()]))
            .await
            .unwrap();
        assert_eq!(ids(&result), ["fixture-version-regex"]);

        let result = h
            .scan(run(&|r| r.template_ids = vec!["Fixture-Token".into()]))
            .await
            .unwrap();
        assert_eq!(ids(&result), ["fixture-token"]);

        let error = h
            .scan(run(&|r| r.tags = vec!["nothing-has-this-tag".into()]))
            .await
            .unwrap_err();
        assert!(error.contains("No applicable templates"), "{error}");
    }

    #[tokio::test]
    async fn dos_templates_never_run_and_intrusive_ones_need_the_switch() {
        let h = Harness::new();
        h.write(
            "target/app.conf",
            "OXAUDIT-FIXTURE-MARKER DOS-FIXTURE-MARKER INTRUSIVE-FIXTURE-MARKER",
        );
        let base = h.adhoc(&[("marker", WORD), ("dos", DOS), ("intrusive", INTRUSIVE)]);

        let result = h.scan(base.clone_for_test()).await.unwrap();
        assert_eq!(ids(&result), ["fixture-marker-word"]);
        assert_eq!(result.state, "completed", "not evaluated is not incomplete");
        let reason = |id: &str| {
            result
                .not_evaluated
                .iter()
                .find(|row| row.template_id == id)
                .map(|row| row.reason.clone())
                .unwrap_or_default()
        };
        assert!(
            reason("fixture-dos").contains("`dos`"),
            "{}",
            reason("fixture-dos")
        );
        assert!(reason("fixture-intrusive").contains("`intrusive`"));
        assert!(result
            .notes
            .iter()
            .any(|n| n.contains("2 template(s) or template checks were not evaluated")));

        let mut with_intrusive = base.clone_for_test();
        with_intrusive.include_intrusive = true;
        let result = h.scan(with_intrusive).await.unwrap();
        assert_eq!(ids(&result), ["fixture-intrusive", "fixture-marker-word"]);
        assert!(result
            .not_evaluated
            .iter()
            .any(|row| row.template_id == "fixture-dos" && row.reason.contains("never runs")));
        assert!(
            !result
                .matches
                .iter()
                .any(|m| m.template_id == "fixture-dos"),
            "dos never runs even with include_intrusive"
        );

        // Asking for the dos template by tag still runs nothing.
        let mut only_dos = base.clone_for_test();
        only_dos.include_intrusive = true;
        only_dos.tags = vec!["dos".into()];
        let error = h.scan(only_dos).await.unwrap_err();
        assert!(error.contains("No applicable templates"), "{error}");
    }

    #[tokio::test]
    async fn network_only_templates_are_listed_as_needing_a_live_target() {
        let h = Harness::new();
        h.write("target/app.conf", "OXAUDIT-FIXTURE-MARKER");
        let result = h
            .scan(h.adhoc(&[("marker", WORD), ("http", HTTP_ONLY)]))
            .await
            .unwrap();
        assert_eq!(result.templates_loaded, 2);
        assert_eq!(result.templates_run, 1);
        assert_eq!(result.state, "completed");
        let row = &result.not_evaluated[0];
        assert_eq!(row.template_id, "fixture-http-only");
        assert_eq!(row.protocol.as_deref(), Some("http"));
        assert!(row.reason.contains("needs a live target"), "{}", row.reason);
    }

    #[tokio::test]
    async fn unsupported_templates_are_listed_with_their_reason_and_warned_on_the_run() {
        let h = Harness::new();
        h.write("target/app.conf", "OXAUDIT-FIXTURE-MARKER");
        let result = h
            .scan(h.adhoc(&[("marker", WORD), ("headless", HEADLESS)]))
            .await
            .unwrap();
        assert_eq!(result.state, "completed");
        assert_eq!(result.matches.len(), 1);
        let row = result
            .not_evaluated
            .iter()
            .find(|row| row.template_id == "fixture-headless")
            .expect("listed");
        assert!(row.reason.contains("headless"), "{}", row.reason);
        assert_eq!(row.pack, "adhoc");
        assert_eq!(row.file, "extra1/headless.yaml");
        let run = h
            .repository()
            .canonical_load_run(&RunId::parse(result.run_id).unwrap())
            .unwrap()
            .unwrap();
        assert!(run
            .warnings
            .iter()
            .any(|w| w.code == "template_not_evaluated"));
    }

    #[tokio::test]
    async fn a_file_that_does_not_load_and_a_repeated_id_are_listed() {
        let h = Harness::new();
        h.write("target/app.conf", "OXAUDIT-FIXTURE-MARKER");
        h.write("tpl/broken.yaml", "id: broken\ninfo: [not, a, mapping\n");
        h.write("tpl/workflow.yaml", "workflows:\n  - template: x.yaml\n");
        let result = h
            .scan(h.adhoc(&[("marker", WORD), ("marker2", WORD)]))
            .await
            .unwrap();
        assert_eq!(result.matches.len(), 1, "the first copy of the id is used");
        let reasons: Vec<_> = result
            .not_evaluated
            .iter()
            .map(|r| (r.file.clone(), r.reason.clone()))
            .collect();
        assert!(reasons.iter().any(
            |(file, reason)| file == "extra1/broken.yaml" && reason.starts_with("did not load")
        ));
        assert!(reasons
            .iter()
            .any(|(_, reason)| reason.contains("duplicate template id")));
        assert!(
            !reasons
                .iter()
                .any(|(file, _)| file == "extra1/workflow.yaml"),
            "YAML with no top-level id is ignored, not reported as an error"
        );
    }

    #[tokio::test]
    async fn zero_applicable_templates_fail_the_scan_instead_of_reporting_no_matches() {
        let h = Harness::new();
        h.write("target/app.conf", "OXAUDIT-FIXTURE-MARKER");

        // Nothing installed and nothing given.
        let req = TemplateScanRequest {
            path: Some(h.dir.path().join("target").to_string_lossy().into_owned()),
            ..Default::default()
        };
        let error = h.scan(req).await.unwrap_err();
        assert!(error.contains("No applicable templates"), "{error}");
        assert!(error.contains("no scan was run"), "{error}");
        let snapshot = h.state.scan_work.snapshot().unwrap();
        assert_eq!(snapshot.recent[0].status, "failed");
        assert_eq!(
            h.run_state(&snapshot.recent[0].run_id.clone().unwrap()),
            RunState::Failed
        );

        // Templates exist but none can run on a local path.
        let error = h
            .scan(h.adhoc(&[("http", HTTP_ONLY), ("headless", HEADLESS)]))
            .await
            .unwrap_err();
        assert!(error.contains("No applicable templates"), "{error}");
        assert!(
            error.contains("2 template(s) were not evaluated"),
            "{error}"
        );
        // Each exclusion cause is counted, so the message is accurate.
        assert!(
            error.contains("2 template(s) were loaded, but none can run:"),
            "{error}"
        );
        assert!(
            error.contains("1 use features this engine does not evaluate"),
            "{error}"
        );
        assert!(
            error.contains("1 are not file-protocol templates for a local path scan"),
            "{error}"
        );
        assert!(!error.contains("filters"), "{error}");
    }

    #[tokio::test]
    async fn credential_templates_are_masked_in_the_result_projection_graph_and_events() {
        const SECRET_VALUE: &str = "Zx9Qw3Lm7Rt2Vb5Nc8Kd";
        let h = Harness::new();
        h.write(
            "target/app.env",
            format!("# creds\nFIXTURE_TOKEN={SECRET_VALUE}\n"),
        );
        let events: Arc<std::sync::Mutex<Vec<Value>>> = Default::default();
        let sink = events.clone();
        let result = h
            .scan_with(
                h.adhoc(&[("secret", SECRET)]),
                Arc::new(move |payload| sink.lock().unwrap().push(payload)),
            )
            .await
            .unwrap();
        let row = &result.matches[0];
        assert_eq!(row.template_id, "fixture-token");
        assert_eq!(
            row.extracted,
            vec![(
                "value".to_string(),
                vec!["Zx9Q\u{2026} (20 chars)".to_string()]
            )]
        );
        // The matcher span and the extractor span are both located; each is
        // masked down to its prefix and length.
        assert!(row.lines.iter().all(|line| line.line == 2));
        assert_eq!(row.lines[0].text, "FIXT\u{2026} (34 chars)");
        assert!(row
            .lines
            .iter()
            .all(|line| line.text.contains("chars)") && !line.text.contains(SECRET_VALUE)));

        let run_id = RunId::parse(result.run_id.clone()).unwrap();
        let mut everything = serde_json::to_string(&result).unwrap();
        everything.push_str(
            &serde_json::to_string(
                &h.repository()
                    .canonical_load_projection(&run_id)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
        );
        let (artifacts, _, observations) =
            h.repository().canonical_load_report_graph(&run_id).unwrap();
        everything.push_str(&serde_json::to_string(&artifacts).unwrap());
        for record in &observations {
            everything.push_str(&serde_json::to_string(&record.observation).unwrap());
            everything.push_str(&serde_json::to_string(&record.evidence).unwrap());
        }
        everything.push_str(
            &serde_json::to_string(&h.repository().canonical_load_run(&run_id).unwrap()).unwrap(),
        );
        everything.push_str(&serde_json::to_string(&events.lock().unwrap().clone()).unwrap());
        assert!(!everything.contains(SECRET_VALUE), "the credential leaked");
        assert!(
            !everything.contains("FIXTURE_TOKEN="),
            "matched text leaked"
        );
    }

    #[tokio::test]
    async fn archive_templates_are_listed_as_not_evaluated_for_archives() {
        let h = Harness::new();
        h.write("target/a.cfg", "ARCHIVE-FIXTURE-MARKER");
        let result = h.scan(h.adhoc(&[("archive", ARCHIVE)])).await.unwrap();
        assert_eq!(result.matches.len(), 1, "plain files are still searched");
        assert_eq!(result.not_evaluated.len(), 1, "once per template");
        assert!(result.not_evaluated[0].reason.contains("archives"));
        assert_eq!(result.not_evaluated[0].protocol.as_deref(), Some("file"));
    }

    #[tokio::test]
    async fn cancelling_mid_scan_ends_cancelled_and_stores_no_projection() {
        let h = Harness::new();
        for i in 0..200 {
            h.write(&format!("target/f{i:03}.conf"), "OXAUDIT-FIXTURE-MARKER");
        }
        let req = h.adhoc(&[("marker", WORD)]);
        let state = h.state.clone();
        let cancel_on_first_progress: Arc<dyn Fn(Value) + Send + Sync> =
            Arc::new(move |_payload| {
                let _ = state
                    .scan_work
                    .cancel(None, &[crate::scan_work::WorkKind::Template]);
            });
        let error = h
            .scan_with(req, cancel_on_first_progress)
            .await
            .unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
        let snapshot = h.state.scan_work.snapshot().unwrap();
        let receipt = &snapshot.recent[0];
        assert_eq!(receipt.status, "cancelled");
        let run_id = receipt
            .run_id
            .clone()
            .expect("the cancelled work names its run");
        assert_eq!(h.run_state(&run_id), RunState::Cancelled);
        assert!(h
            .repository()
            .canonical_load_projection(&RunId::parse(run_id).unwrap())
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn installed_packs_are_applied_and_recorded_on_the_run() {
        let h = Harness::new();
        h.write("pack/marker.yaml", WORD);
        h.write("pack/http.yaml", HTTP_ONLY);
        let pack = h.install("fixtures", "pack");
        h.write("target/app.conf", "OXAUDIT-FIXTURE-MARKER");
        let req = TemplateScanRequest {
            path: Some(h.dir.path().join("target").to_string_lossy().into_owned()),
            ..Default::default()
        };
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pack, pack.id);
        assert_eq!(
            result.matches[0].rule_id,
            format!("{}/fixture-marker-word", pack.id)
        );
        assert_eq!(result.packs.len(), 1);
        assert_eq!(result.packs[0].license, "Apache-2.0");
        assert_eq!(result.packs[0].template_count, 2);
        let run = h
            .repository()
            .canonical_load_run(&RunId::parse(result.run_id).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            run.rule_pack_ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
            vec![format!("nuclei:{}@{}", pack.id, &pack.content_sha256[..12])]
        );
        assert_eq!(
            run.engine_ids,
            [format!("oxaudit-nuclei/{}", oxaudit_nuclei::VERSION)]
        );
    }

    #[tokio::test]
    async fn a_tampered_pack_makes_the_run_incomplete_with_a_warning() {
        let h = Harness::new();
        h.write("good/marker.yaml", WORD);
        h.write("bad/version.yaml", VERSION);
        let good = h.install("good", "good");
        let bad = h.install("bad", "bad");
        h.write("target/app.conf", "OXAUDIT-FIXTURE-MARKER\nversion = 1.0\n");
        std::fs::write(
            h.dir
                .path()
                .join("data/sigpacks/nuclei")
                .join(&bad.id)
                .join("version.yaml"),
            "id: evil\n",
        )
        .unwrap();
        let req = TemplateScanRequest {
            path: Some(h.dir.path().join("target").to_string_lossy().into_owned()),
            ..Default::default()
        };
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.state, "incomplete");
        assert_eq!(result.matches.len(), 1, "only the verified pack applied");
        assert_eq!(result.matches[0].pack, good.id);
        assert!(result.notes.iter().any(|n| n.contains(&bad.id)));
        assert_eq!(h.run_state(&result.run_id), RunState::Incomplete);
        let run = h
            .repository()
            .canonical_load_run(&RunId::parse(result.run_id).unwrap())
            .unwrap()
            .unwrap();
        assert!(run
            .warnings
            .iter()
            .any(|w| w.code == "template_pack_skipped"));
        assert_eq!(run.rule_pack_ids.len(), 1);
    }

    #[tokio::test]
    async fn invalid_requests_are_rejected_before_any_work() {
        let h = Harness::new();
        let mut req = h.adhoc(&[("marker", WORD)]);
        req.max_file_size_mb = Some(0);
        assert!(h.scan(req).await.unwrap_err().contains("maxFileSizeMb"));
        let error = h.scan(TemplateScanRequest::default()).await.unwrap_err();
        assert!(error.contains("local path"), "{error}");
        let mut req = h.adhoc(&[("marker", WORD)]);
        req.path = Some(h.dir.path().join("missing").to_string_lossy().into_owned());
        assert!(h.scan(req).await.unwrap_err().contains("cannot resolve"));
        assert!(h
            .state
            .scan_work
            .snapshot()
            .unwrap()
            .recent
            .iter()
            .all(|r| r.status != "completed"));
    }

    #[tokio::test]
    async fn match_order_is_deterministic_and_the_target_is_left_untouched() {
        let h = Harness::new();
        for i in 0..40 {
            h.write(
                &format!("target/d{}/f{i:02}.conf", i % 5),
                "OXAUDIT-FIXTURE-MARKER\nversion = 2.0\n",
            );
        }
        let req = h.adhoc(&[("marker", WORD), ("version", VERSION)]);
        let before = std::fs::read_dir(h.dir.path().join("target/d0"))
            .unwrap()
            .count();
        let first = h.scan(req.clone_for_test()).await.unwrap();
        let second = h.scan(req).await.unwrap();
        assert_eq!(first.matches, second.matches);
        assert_eq!(first.matches.len(), 80);
        let paths: Vec<_> = first
            .matches
            .iter()
            .map(|m| m.file_path.clone().unwrap())
            .collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "rows follow the walk order");
        assert_eq!(
            before,
            std::fs::read_dir(h.dir.path().join("target/d0"))
                .unwrap()
                .count()
        );
    }

    // ------------------------------------------------------- live targets
    //
    // Every server below is a loopback listener started by the test; every
    // template is authored here. No external network is used.

    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    fn fast_live() -> crate::models::LiveScanSettings {
        crate::models::LiveScanSettings {
            requests_per_second: 1000,
            timeout_seconds: 5,
            ..Default::default()
        }
    }

    const LIVE_MARKER: &str = r#"id: live-marker
info:
  name: Live marker
  author: oxaudit-tests
  severity: high
  tags: fixture
http:
  - method: GET
    path:
      - "{{BaseURL}}/fixture"
    headers:
      Authorization: "Bearer canary-request-credential"
    matchers:
      - type: word
        name: marker
        words:
          - "OXAUDIT-LIVE-MARKER"
"#;
    const LIVE_TOKEN: &str = r#"id: live-token
info:
  name: Live token
  author: oxaudit-tests
  severity: critical
  tags: token,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/token"
    matchers:
      - type: regex
        name: token
        regex:
          - 'LIVE_TOKEN=[A-Za-z0-9]{20,}'
    extractors:
      - type: regex
        name: value
        group: 1
        regex:
          - 'LIVE_TOKEN=([A-Za-z0-9]{20,})'
"#;
    const LIVE_DOS: &str = r#"id: live-dos
info:
  name: Live dos
  author: oxaudit-tests
  severity: high
  tags: dos
http:
  - method: GET
    path:
      - "{{BaseURL}}/dos"
    matchers:
      - type: status
        status: [200]
"#;
    const LIVE_REDIRECT: &str = r#"id: live-redirect
info:
  name: Live redirect
  author: oxaudit-tests
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/to-name"
      - "{{BaseURL}}/to-port"
    redirects: true
    max-redirects: 3
    matchers:
      - type: status
        status: [302]
"#;
    const LIVE_TOKEN_VALUE: &str = "Qw8Er4Ty6Ui2Op0As3Df";
    const LIVE_SIBLING_SECRET: &str = "sibling-secret-Hj5Kl7";

    fn live_get(id: &str, path: &str) -> String {
        format!(
            "id: {id}\ninfo:\n  name: Live {id}\n  author: oxaudit-tests\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{{{BaseURL}}}}{path}\"\n    matchers:\n      - type: status\n        status: [200]\n"
        )
    }

    fn http_response(status: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status} X\r\n");
        for (name, value) in headers {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ));
        out.into_bytes()
    }

    /// A loopback HTTP server recording every request path it answered.
    struct Loopback {
        port: u16,
        paths: Arc<StdMutex<Vec<String>>>,
    }

    impl Loopback {
        fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        fn hits(&self) -> usize {
            self.paths.lock().unwrap().len()
        }

        fn paths(&self) -> Vec<String> {
            self.paths.lock().unwrap().clone()
        }
    }

    async fn loopback(
        delay: Duration,
        handler: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    ) -> Loopback {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let paths: Arc<StdMutex<Vec<String>>> = Arc::default();
        let handler = Arc::new(handler);
        let seen = paths.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (seen, handler) = (seen.clone(), handler.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        // A TLS ClientHello or an oversized head: hang up.
                        if buf.first() == Some(&0x16) || buf.len() > 64 * 1024 {
                            return;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                    seen.lock().unwrap().push(path.clone());
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let _ = socket.write_all(&handler(&path)).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Loopback { port, paths }
    }

    /// A listener that must never be contacted; counts connections.
    async fn tripwire() -> (u16, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let contacts = Arc::new(AtomicUsize::new(0));
        let count = contacts.clone();
        tokio::spawn(async move {
            while let Ok((_socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
            }
        });
        (port, contacts)
    }

    async fn closed_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    fn fixture_handler(trip_port: u16) -> impl Fn(&str) -> Vec<u8> + Send + Sync + 'static {
        move |path| match path {
            "/fixture" => http_response(
                200,
                &[("Set-Cookie", "session=canary-response-cookie")],
                "hello OXAUDIT-LIVE-MARKER world",
            ),
            "/token" => http_response(
                200,
                &[],
                &format!("LIVE_TOKEN={LIVE_TOKEN_VALUE}\nOTHER={LIVE_SIBLING_SECRET}\n"),
            ),
            "/to-name" => http_response(302, &[("Location", "http://offscope.invalid/stolen")], ""),
            "/to-port" => http_response(
                302,
                &[("Location", &format!("http://127.0.0.1:{trip_port}/stolen"))],
                "",
            ),
            _ => http_response(404, &[], "not here"),
        }
    }

    impl Harness {
        /// A live request for `targets` with the given one-off templates.
        fn live(&self, templates: &[(&str, &str)], targets: &[String]) -> TemplateScanRequest {
            let mut request = self.adhoc(templates);
            request.path = None;
            request.targets = targets.to_vec();
            request.authorization = Some(crate::template::TemplateAuthorization {
                acknowledged: true,
                statement: "Loopback fixture owned by this test".into(),
            });
            request
        }

        fn run(&self, run_id: &str) -> oxaudit_domain::Run {
            self.repository()
                .canonical_load_run(&RunId::parse(run_id).unwrap())
                .unwrap()
                .unwrap()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_scan_records_a_redacted_exchange_a_network_graph_and_the_authorization() {
        let h = Harness::new();
        let (trip, _) = tripwire().await;
        let server = loopback(Duration::ZERO, fixture_handler(trip)).await;
        let target = server.url();
        let mut request = h.live(
            &[
                ("marker", LIVE_MARKER),
                ("token", LIVE_TOKEN),
                ("dos", LIVE_DOS),
            ],
            std::slice::from_ref(&target),
        );
        request.include_intrusive = true;
        let events: Arc<StdMutex<Vec<Value>>> = Arc::default();
        let sink = events.clone();
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let result = h
            .scan_live(
                request,
                &fast_live(),
                Arc::new(move |payload| sink.lock().unwrap().push(payload)),
            )
            .await
            .unwrap();

        assert_eq!(result.state, "completed", "{:?}", result.notes);
        assert_eq!(result.mode, "targets");
        assert_eq!(result.target, target);
        assert_eq!(result.templates_run, 2, "dos never runs");
        assert_eq!(result.requests_sent, server.hits() as u64);
        assert_eq!(result.requests_refused, 0);
        let mut paths = server.paths();
        paths.sort();
        assert_eq!(paths, ["/fixture", "/token"], "nothing else was requested");
        assert!(
            result
                .not_evaluated
                .iter()
                .any(|row| row.template_id == "live-dos" && row.reason.contains("`dos`")),
            "{:?}",
            result.not_evaluated
        );

        let marker = result
            .matches
            .iter()
            .find(|row| row.template_id == "live-marker")
            .expect("the marker matched");
        assert_eq!(marker.protocol, "http");
        assert_eq!(marker.file_path, None);
        assert_eq!(marker.matcher_names, ["marker"]);
        let exchange = marker
            .exchange
            .as_ref()
            .expect("a live match has an exchange");
        assert_eq!(exchange.protocol, "http");
        assert_eq!(exchange.target, target);
        assert!(
            exchange
                .request
                .starts_with(&format!("GET {target}/fixture HTTP/1.1")),
            "{}",
            exchange.request
        );
        assert!(exchange.request.contains("Authorization: [REDACTED]"));
        assert!(exchange.response_excerpt.contains("OXAUDIT-LIVE-MARKER"));
        assert!(exchange.response_excerpt.contains("Set-Cookie: [REDACTED]"));
        println!(
            "target-mode row: {}",
            serde_json::to_string_pretty(marker).unwrap()
        );

        let token = result
            .matches
            .iter()
            .find(|row| row.template_id == "live-token")
            .expect("the token template matched");
        assert_eq!(
            token.extracted,
            vec![(
                "value".to_string(),
                vec!["Qw8E\u{2026} (20 chars)".to_string()]
            )]
        );
        let token_exchange = token.exchange.as_ref().unwrap();
        assert!(token_exchange
            .response_excerpt
            .ends_with("[response body withheld: this template reports credentials]"));
        assert!(token_exchange.response_truncated);

        // Authorization: in the result, the projection, and the durable run.
        let authorization = result.authorization.as_ref().expect("recorded");
        assert!(authorization.acknowledged);
        assert_eq!(
            authorization.statement,
            "Loopback fixture owned by this test"
        );
        assert!(authorization.acknowledged_at_ms >= before);
        let run_id = RunId::parse(result.run_id.clone()).unwrap();
        let projection = h
            .repository()
            .canonical_load_projection(&run_id)
            .unwrap()
            .expect("projection is stored");
        assert_eq!(projection["authorization"]["acknowledged"], true);
        assert_eq!(
            projection["authorization"]["statement"],
            "Loopback fixture owned by this test"
        );
        assert!(
            projection["authorization"]["acknowledgedAtMs"]
                .as_u64()
                .unwrap()
                >= before
        );
        println!(
            "stored authorization: {}",
            serde_json::to_string_pretty(&projection["authorization"]).unwrap()
        );
        assert!(projection["refusedHosts"].as_array().unwrap().is_empty());
        assert!(projection["resolved"].as_array().is_some());
        let run = h.run(&result.run_id);
        assert_eq!(run.state, RunState::Completed);
        let receipt = run
            .warnings
            .iter()
            .find(|w| w.code == "live_scan_authorization")
            .expect("the authorization receipt is on the run");
        assert!(receipt
            .message
            .contains("Loopback fixture owned by this test"));
        assert!(receipt.message.contains(&target));
        assert!(receipt
            .message
            .contains(&authorization.acknowledged_at_ms.to_string()));
        // The acknowledgement is per run: settings never hold it.
        assert_eq!(
            h.state.settings.lock().unwrap().live_scan,
            crate::models::LiveScanSettings::default()
        );

        // Graph: one NetworkTarget artifact, NetworkExchange evidence on it.
        let (artifacts, _, observations) =
            h.repository().canonical_load_report_graph(&run_id).unwrap();
        assert_eq!(artifacts.len(), 1, "one artifact per matched target");
        assert_eq!(
            artifacts[0].kind,
            oxaudit_domain::ArtifactKind::NetworkTarget
        );
        assert_eq!(artifacts[0].location.normalized_path, target);
        assert_eq!(observations.len(), 2);
        for record in &observations {
            assert_eq!(record.observation.kind, ObservationKind::TemplateMatch);
            assert_eq!(record.observation.artifact_id, artifacts[0].id);
            match &record.evidence[0].evidence {
                oxaudit_domain::Evidence::NetworkExchange(evidence) => {
                    assert_eq!(evidence.artifact_id, artifacts[0].id);
                    assert_eq!(evidence.target, target);
                }
                other => panic!("unexpected evidence {other:?}"),
            }
        }

        // Nothing credential-bearing reached any stored or emitted form.
        let mut everything = serde_json::to_string(&result).unwrap();
        everything.push_str(&serde_json::to_string(&projection).unwrap());
        for record in &observations {
            everything.push_str(&serde_json::to_string(&record.observation).unwrap());
            everything.push_str(&serde_json::to_string(&record.evidence).unwrap());
        }
        everything.push_str(&serde_json::to_string(&run).unwrap());
        everything.push_str(&serde_json::to_string(&*events.lock().unwrap()).unwrap());
        for canary in [
            LIVE_TOKEN_VALUE,
            LIVE_SIBLING_SECRET,
            "canary-request-credential",
            "canary-response-cookie",
        ] {
            assert!(!everything.contains(canary), "{canary} leaked");
        }

        // Progress events carry the live counters.
        let events = events.lock().unwrap();
        let last = events.last().expect("progress was emitted");
        for key in [
            "operationId",
            "message",
            "done",
            "total",
            "requestsSent",
            "matches",
        ] {
            assert!(!last[key].is_null(), "{key} missing from {last}");
        }
        assert_eq!(last["matches"], 2);
        assert_eq!(last["done"], last["total"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_scan_without_an_acknowledgement_or_with_a_bad_target_creates_no_run() {
        let h = Harness::new();
        let server = loopback(Duration::ZERO, fixture_handler(9)).await;
        let mut request = h.live(&[("marker", LIVE_MARKER)], &[server.url()]);

        for authorization in [
            None,
            Some(crate::template::TemplateAuthorization {
                acknowledged: false,
                statement: "not confirmed".into(),
            }),
        ] {
            request.authorization = authorization;
            let error = h.scan(request.clone_for_test()).await.unwrap_err();
            assert!(
                error.contains("requires an explicit authorization"),
                "{error}"
            );
        }

        request.authorization = Some(crate::template::TemplateAuthorization {
            acknowledged: true,
            statement: String::new(),
        });
        request.targets = vec![server.url(), "http://bad host".into()];
        let error = h.scan(request.clone_for_test()).await.unwrap_err();
        assert!(error.contains("`http://bad host`"), "{error}");
        assert!(error.contains("nothing was sent"), "{error}");

        request.targets = vec![server.url()];
        let mut settings = fast_live();
        settings.proxy = Some("socks5://proxy.invalid:1080".into());
        let error = h
            .scan_live(request.clone_for_test(), &settings, Arc::new(|_| {}))
            .await
            .unwrap_err();
        assert!(error.contains("proxy"), "{error}");
        settings.proxy = Some("http://user:pw@proxy.invalid:3128".into());
        let error = h
            .scan_live(request, &settings, Arc::new(|_| {}))
            .await
            .unwrap_err();
        assert!(error.contains("user name or password"), "{error}");
        assert!(!error.contains("pw@"), "{error}");

        assert_eq!(server.hits(), 0, "nothing was sent");
        assert!(
            h.state.scan_work.snapshot().unwrap().recent.is_empty(),
            "no work was started"
        );
        assert!(h
            .repository()
            .canonical_list_runs(None, 10)
            .unwrap()
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_off_scope_redirect_is_refused_counted_and_the_run_still_completes() {
        let h = Harness::new();
        let (trip, contacts) = tripwire().await;
        let server = loopback(Duration::ZERO, fixture_handler(trip)).await;
        let result = h
            .scan(h.live(&[("redirect", LIVE_REDIRECT)], &[server.url()]))
            .await
            .unwrap();
        assert_eq!(result.state, "completed", "{:?}", result.notes);
        assert_eq!(
            contacts.load(Ordering::SeqCst),
            0,
            "off-scope port contacted"
        );
        assert_eq!(result.requests_sent, 2);
        assert_eq!(result.requests_refused, 2);
        assert!(result
            .refused_hosts
            .contains(&"offscope.invalid".to_string()));
        assert!(result.refused_hosts.contains(&"127.0.0.1".to_string()));
        assert!(result.notes.iter().any(|n| n.contains("refused by scope")));
        let projection = h
            .repository()
            .canonical_load_projection(&RunId::parse(result.run_id).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(projection["requestsRefused"], 2);
        assert!(projection["refusedHosts"]
            .as_array()
            .unwrap()
            .contains(&json!("offscope.invalid")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreachable_target_is_not_evaluated_and_makes_the_run_incomplete() {
        let h = Harness::new();
        let port = closed_port().await;
        let target = format!("http://127.0.0.1:{port}");
        let result = h
            .scan(h.live(&[("marker", LIVE_MARKER)], std::slice::from_ref(&target)))
            .await
            .unwrap();
        assert_eq!(result.state, "incomplete");
        assert!(result.matches.is_empty());
        assert!(result
            .not_evaluated
            .iter()
            .any(|row| row.template_id == "live-marker"
                && row.target.as_deref() == Some(target.as_str())));
        assert_eq!(result.unreachable_targets.len(), 1);
        assert_eq!(result.unreachable_targets[0].target, target);
        let run = h.run(&result.run_id);
        assert_eq!(run.state, RunState::Incomplete);
        assert!(run
            .warnings
            .iter()
            .any(|w| w.code == "template_target_unreachable"));
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .to_lowercase()
            .contains("clean"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_scan_that_evaluates_nothing_is_incomplete_not_completed() {
        // An IP target with only a DNS template: nothing can be asked.
        let h = Harness::new();
        let dns_only = "id: live-dns-only\ninfo:\n  name: DNS only\n  severity: info\ndns:\n  - name: \"{{FQDN}}\"\n    type: A\n    matchers:\n      - type: word\n        words: [IN]\n";
        let result = h
            .scan(h.live(&[("dns", dns_only)], &["10.0.0.9".to_string()]))
            .await
            .unwrap();
        assert_eq!(result.state, "incomplete", "{:?}", result.notes);
        assert_eq!(result.requests_sent, 0);
        assert!(result.incomplete_reasons.iter().any(|r| r
            .contains("1 template(s) were selected against 1 target(s)")
            && r.contains("none could be evaluated")));
        assert_eq!(result.unreachable_targets.len(), 1);
        let run = h.run(&result.run_id);
        assert_eq!(run.state, RunState::Incomplete);
        assert!(run
            .warnings
            .iter()
            .any(|w| w.code == "template_nothing_evaluated"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaching_the_request_budget_makes_the_run_incomplete() {
        let h = Harness::new();
        let server = loopback(Duration::ZERO, |_| http_response(200, &[], "ok")).await;
        let templates: Vec<(String, String)> = (0..6)
            .map(|i| (format!("get{i}"), live_get(&format!("live-get-{i}"), "/")))
            .collect();
        let borrowed: Vec<(&str, &str)> = templates
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect();
        let settings = crate::models::LiveScanSettings {
            max_requests: 2,
            per_host_concurrency: 1,
            ..fast_live()
        };
        let result = h
            .scan_live(
                h.live(&borrowed, &[server.url()]),
                &settings,
                Arc::new(|_| {}),
            )
            .await
            .unwrap();
        assert_eq!(result.state, "incomplete");
        assert_eq!(result.requests_sent, 2);
        assert_eq!(server.hits(), 2);
        let run = h.run(&result.run_id);
        assert_eq!(run.state, RunState::Incomplete);
        assert!(run
            .warnings
            .iter()
            .any(|w| w.code == "template_request_budget"));
        assert!(result.notes.iter().any(|n| n.contains("request budget")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_live_scan_ends_cancelled_and_stores_no_projection() {
        let h = Harness::new();
        let server = loopback(Duration::from_millis(100), |_| {
            http_response(200, &[], "ok")
        })
        .await;
        let templates: Vec<(String, String)> = (0..30)
            .map(|i| (format!("get{i}"), live_get(&format!("live-get-{i}"), "/")))
            .collect();
        let borrowed: Vec<(&str, &str)> = templates
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect();
        let settings = crate::models::LiveScanSettings {
            per_host_concurrency: 1,
            ..fast_live()
        };
        let state = h.state.clone();
        let cancel_after_first_check: Arc<dyn Fn(Value) + Send + Sync> = Arc::new(move |payload| {
            if payload["done"].as_u64().unwrap_or(0) >= 1 {
                let _ = state
                    .scan_work
                    .cancel(None, &[crate::scan_work::WorkKind::Template]);
            }
        });
        let error = h
            .scan_live(
                h.live(&borrowed, &[server.url()]),
                &settings,
                cancel_after_first_check,
            )
            .await
            .unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
        let receipt = &h.state.scan_work.snapshot().unwrap().recent[0];
        assert_eq!(receipt.status, "cancelled");
        let run_id = receipt.run_id.clone().unwrap();
        assert_eq!(h.run_state(&run_id), RunState::Cancelled);
        assert!(h
            .repository()
            .canonical_load_projection(&RunId::parse(run_id).unwrap())
            .unwrap()
            .is_none());
        let hits = server.hits();
        assert!(hits < 30, "{hits} requests were sent");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            server.hits(),
            hits,
            "nothing is sent after the scan returns"
        );
    }

    impl TemplateScanRequest {
        /// `TemplateScanRequest` is deserialize-only in production code; the
        /// tests re-run the same request several times.
        fn clone_for_test(&self) -> Self {
            Self {
                path: self.path.clone(),
                targets: self.targets.clone(),
                authorization: self.authorization.clone(),
                pack_ids: self.pack_ids.clone(),
                extra_template_paths: self.extra_template_paths.clone(),
                tags: self.tags.clone(),
                exclude_tags: self.exclude_tags.clone(),
                severities: self.severities.clone(),
                template_ids: self.template_ids.clone(),
                include_intrusive: self.include_intrusive,
                rate_limit: self.rate_limit,
                max_file_size_mb: self.max_file_size_mb,
                operation_id: self.operation_id.clone(),
            }
        }
    }
}

#[cfg(all(test, not(feature = "templates")))]
mod no_engine_tests {
    use super::*;

    struct Quiet;
    impl crate::findings::service::ScanEventSink for Quiet {
        fn emit(&self, _event: &str, _payload: Value) -> Result<(), CommandError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn scan_templates_without_the_engine_fails_instead_of_returning_an_empty_result() {
        let findings = FindingsState::available(FindingsService::new(
            crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
        ));
        let packs = SigPacksState::unavailable("none".into());
        let error = scan_templates_engine(
            &crate::scan_work::ScanWorkRegistry::default(),
            &findings,
            &packs,
            &Quiet,
            Arc::new(|_| {}),
            TemplateScanRequest::default(),
            &crate::models::LiveScanSettings::default(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("no template engine"), "{error}");
    }
}
