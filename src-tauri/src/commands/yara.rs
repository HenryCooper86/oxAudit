//! The YARA scan command.
//!
//! Follows the binary scan's lifecycle exactly: a work lease, a canonical
//! run with state transitions, run warnings for anything that narrows
//! coverage, a stored projection, and a terminal state that says what was
//! and was not evaluated. Zero matches means "no rule matched"; it is never
//! a statement about the scanned content.

use super::*;

use crate::sigpacks::SigPacksState;
use crate::yara::{YaraScanRequest, YaraScanResult};

/// Scan a file or folder with imported YARA rules.
///
/// Emits `yara://progress` (throttled) and the usual `run://event` stream;
/// cancel it with `cancel_scan_work`.
#[tauri::command]
pub async fn scan_yara(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    sig_packs: State<'_, SigPacksState>,
    request: YaraScanRequest,
) -> Result<YaraScanResult, String> {
    struct TauriEvents(AppHandle);
    impl crate::findings::service::ScanEventSink for TauriEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let progress_app = app.clone();
    let progress: Arc<dyn Fn(Value) + Send + Sync> = Arc::new(move |payload| {
        let _ = progress_app.emit("yara://progress", payload);
    });
    scan_yara_engine(
        &state.scan_work,
        &findings,
        &sig_packs,
        &TauriEvents(app),
        progress,
        request,
    )
    .await
}

#[cfg(not(feature = "yara"))]
pub(crate) async fn scan_yara_engine(
    _scan_work: &crate::scan_work::ScanWorkRegistry,
    _findings: &FindingsState,
    _packs: &SigPacksState,
    _events: &dyn crate::findings::service::ScanEventSink,
    _progress: Arc<dyn Fn(Value) + Send + Sync>,
    _request: YaraScanRequest,
) -> Result<YaraScanResult, String> {
    Err("This build of oxAudit has no YARA engine, so no scan was run. Install a build with the `yara` feature.".into())
}

#[cfg(feature = "yara")]
pub(crate) use engine::scan_yara_engine;

#[cfg(feature = "yara")]
mod engine {
    use oxaudit_domain::{RulePackId, RunKind, RunState};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::sigpacks::{PackKind, ResolvedSigPacks};
    use crate::yara::graph;
    use crate::yara::scan::{self, PackInput, ScanLimits};
    use crate::yara::{
        max_file_bytes, YaraPackInfo, YaraRuleSkip, ADHOC_PACK_ID, MAX_FILES, MAX_MATCH_ROWS,
    };

    fn stage(
        managed: &mut Option<oxaudit_application::ManagedRun<'_>>,
        state: RunState,
    ) -> Result<(), String> {
        managed
            .as_mut()
            .expect("yara run exists")
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

    /// Rule files supplied for this scan only.
    struct AdhocRules {
        files: Vec<crate::sigpacks::PackFile>,
        skips: Vec<YaraRuleSkip>,
        sha256: String,
        sources: Vec<String>,
    }

    fn collect_adhoc(paths: &[String]) -> Result<Option<AdhocRules>, String> {
        if paths.is_empty() {
            return Ok(None);
        }
        let mut files = Vec::new();
        let mut skips = Vec::new();
        let mut sources = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let collected = crate::sigpacks::collect_source(PackKind::Yara, Path::new(path))
                .map_err(|error| format!("rules {path}: {error}"))?;
            let prefix = format!("extra{}", index + 1);
            sources.push(format!("{prefix} = {path}"));
            for skip in collected.skipped {
                skips.push(YaraRuleSkip {
                    pack: ADHOC_PACK_ID.into(),
                    file: format!("{prefix}/{}", skip.file),
                    line: skip.line,
                    message: skip.message,
                });
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
        Ok(Some(AdhocRules {
            files,
            skips,
            sha256: hex::encode(hasher.finalize()),
            sources,
        }))
    }

    fn zero_rules_error(
        resolved_skipped: &[(String, String)],
        store_error: Option<&str>,
        compile_skips: &[YaraRuleSkip],
        had_sources: bool,
    ) -> String {
        let mut message = String::from(
            "No YARA rules are available to scan with, so no scan was run (a scan with no rules cannot report \"no rule matched\").",
        );
        if had_sources {
            message.push_str(" Rule files were found, but none of them compiled.");
        } else if !resolved_skipped.is_empty() {
            message.push_str(
                " Enabled YARA pack(s) are installed, but every one failed verification and was not applied, and no one-off rule files were given.",
            );
        } else if !compile_skips.is_empty() {
            message.push_str(
                " The rule files given could not be read or compiled, and no installed pack supplied any.",
            );
        } else {
            message.push_str(
                " No enabled YARA pack is installed and no one-off rule files were given; import a pack or pass rule files.",
            );
        }
        if let Some(error) = store_error {
            message.push_str(&format!(
                " The signature-pack store is unavailable: {error}."
            ));
        }
        for (id, reason) in resolved_skipped.iter().take(5) {
            message.push_str(&format!(" Pack {id} was not applied: {reason}."));
        }
        if let Some(first) = compile_skips.first() {
            message.push_str(&format!(
                " {} rule file(s) did not compile; first: {}/{}: {}.",
                compile_skips.len(),
                first.pack,
                first.file,
                first.message
            ));
        }
        message
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn scan_yara_engine(
        scan_work: &crate::scan_work::ScanWorkRegistry,
        findings: &FindingsState,
        packs: &SigPacksState,
        events: &dyn crate::findings::service::ScanEventSink,
        progress: Arc<dyn Fn(Value) + Send + Sync>,
        request: YaraScanRequest,
    ) -> Result<YaraScanResult, String> {
        let max_bytes = max_file_bytes(&request)?;
        let started = std::time::Instant::now();
        let mut work = scan_work.begin(
            crate::scan_work::WorkKind::Yara,
            &request.path,
            request.operation_id.as_deref(),
            events,
        )?;
        let cancel = work.cancellation();
        let operation_id = work.id().to_owned();

        let target = Path::new(&request.path)
            .canonicalize()
            .map_err(|error| format!("cannot resolve the YARA scan target: {error}"))?;
        // Reading rule files and re-verifying packs is file I/O and hashing:
        // it runs on a blocking thread, never on an async runtime worker.
        let adhoc_paths = request.extra_rule_paths.clone();
        let adhoc = tokio::task::spawn_blocking(move || collect_adhoc(&adhoc_paths))
            .await
            .map_err(|error| format!("reading the rule files did not finish: {error}"))??;

        // Installed packs, re-verified against their manifests. A pack that
        // fails is reported and makes the run Incomplete; it never silently
        // narrows the rule set.
        let mut store_error: Option<String> = None;
        let resolved = match (packs.shared(), request.pack_ids.as_deref()) {
            // An explicit empty selection means "no installed packs": the
            // store is not consulted and its absence is not a coverage gap.
            (_, Some([])) => ResolvedSigPacks::default(),
            (Ok(store), ids) => {
                let (store, ids) = (store.clone(), ids.map(<[String]>::to_vec));
                tokio::task::spawn_blocking(move || store.resolve(PackKind::Yara, ids.as_deref()))
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
        let mut run =
            oxaudit_domain::Run::queued(RunKind::Yara, target.to_string_lossy(), epoch_millis());
        run.engine_ids = vec![format!("yara-x/{}", oxaudit_yara::YARA_X_VERSION)];
        run.rule_pack_ids = resolved
            .packs
            .iter()
            .map(|pack| {
                RulePackId::parse(format!(
                    "yara:{}@{}",
                    pack.record.id,
                    &pack.record.content_sha256[..12]
                ))
                .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()?;
        let mut managed = Some(coordinator.begin(run).map_err(|error| error.to_string())?);
        work.bind_run(managed.as_ref().expect("yara run exists").run().id.as_str());
        stage(&mut managed, RunState::Discovering)?;

        let pack_infos_input: Vec<(
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
            warn(&mut managed, "yara_pack_skipped", message.clone());
            incomplete_reasons.push(message);
        }
        if let Some(error) = &store_error {
            let message = format!(
                "The signature-pack store is unavailable, so installed packs were not applied: {error}"
            );
            warn(&mut managed, "yara_pack_store_unavailable", message.clone());
            incomplete_reasons.push(message);
        }
        if let Some(adhoc) = &adhoc {
            warn(
                &mut managed,
                "yara_adhoc_rules",
                format!(
                    "One-off rule files were applied (content sha256 {}): {}",
                    adhoc.sha256,
                    adhoc.sources.join("; ")
                ),
            );
        }

        let outcome: Result<YaraScanResult, String> = async {
            // ---- rules
            let mut inputs: Vec<PackInput> = Vec::new();
            let mut infos: Vec<YaraPackInfo> = Vec::new();
            for (record, files) in pack_infos_input {
                infos.push(YaraPackInfo {
                    id: record.id.clone(),
                    name: record.name.clone(),
                    license: record.license.clone(),
                    content_sha256: record.content_sha256.clone(),
                    rule_count: 0,
                });
                inputs.push(PackInput {
                    id: record.id,
                    files,
                });
            }
            let mut adhoc_skips: Vec<YaraRuleSkip> = Vec::new();
            if let Some(adhoc) = adhoc {
                infos.push(YaraPackInfo {
                    id: ADHOC_PACK_ID.into(),
                    name: "One-off rule files".into(),
                    license: "not recorded (rules supplied for this scan only)".into(),
                    content_sha256: adhoc.sha256,
                    rule_count: 0,
                });
                adhoc_skips = adhoc.skips;
                inputs.push(PackInput {
                    id: ADHOC_PACK_ID.into(),
                    files: adhoc.files,
                });
            }
            let had_sources = inputs.iter().any(|input| !input.files.is_empty());
            if !had_sources {
                return Err(zero_rules_error(
                    &resolved_skipped,
                    store_error.as_deref(),
                    &adhoc_skips,
                    false,
                ));
            }
            let compiled = tokio::task::spawn_blocking(move || scan::compile(&inputs))
                .await
                .map_err(|error| format!("rule compilation did not finish: {error}"))??;
            let mut rules_skipped = compiled.skips.clone();
            let mut rules_skipped_total = compiled.skips_total;
            for skip in adhoc_skips {
                rules_skipped_total += 1;
                if rules_skipped.len() < crate::yara::MAX_RULE_SKIP_ROWS {
                    rules_skipped.push(skip);
                }
            }
            let rules_compiled = compiled.set.rules().len();
            if rules_compiled == 0 {
                return Err(zero_rules_error(
                    &resolved_skipped,
                    store_error.as_deref(),
                    &rules_skipped,
                    true,
                ));
            }
            for info in &mut infos {
                info.rule_count = compiled.rules_per_pack.get(&info.id).copied().unwrap_or(0);
            }
            if rules_skipped_total > 0 {
                let first = rules_skipped
                    .iter()
                    .take(3)
                    .map(|skip| format!("{}/{}: {}", skip.pack, skip.file, skip.message))
                    .collect::<Vec<_>>()
                    .join("; ");
                warn(
                    &mut managed,
                    "yara_rules_skipped",
                    format!(
                        "{rules_skipped_total} rule file(s) did not compile and were not applied; first: {first}"
                    ),
                );
            }
            if cancel.load(Ordering::SeqCst) {
                return Err("YARA scan cancelled".into());
            }

            // ---- walk
            let walk_target = target.clone();
            let walk_cancel = cancel.clone();
            let walked = tokio::task::spawn_blocking(move || scan::walk(&walk_target, &walk_cancel))
                .await
                .map_err(|error| format!("the file walk did not finish: {error}"))??;
            if cancel.load(Ordering::SeqCst) || walked.cancelled {
                return Err("YARA scan cancelled".into());
            }
            let mut notes: Vec<String> = Vec::new();
            let over_cap = walked.over_cap;
            if over_cap > 0 {
                let message = format!(
                    "The target holds more than {MAX_FILES} files; {over_cap} were not scanned."
                );
                warn(&mut managed, "yara_file_cap", message.clone());
                incomplete_reasons.push(message);
            }
            let mut skipped = walked.skipped;
            let files = walked.files;
            stage(&mut managed, RunState::Detecting)?;

            // ---- scan
            let compiled = Arc::new(compiled);
            let scan_compiled = compiled.clone();
            let scan_cancel = cancel.clone();
            let scan_progress = progress.clone();
            let scan_operation = operation_id.clone();
            let limits = ScanLimits::new(max_bytes, scan::FILE_TIMEOUT);
            let scanned = tokio::task::spawn_blocking(move || {
                scan::scan_files(
                    &scan_compiled.set,
                    &files,
                    &limits,
                    &scan_cancel,
                    &move |done, total, bytes| {
                        scan_progress(json!({
                            "operationId": scan_operation,
                            "message": format!("Scanned {done} of {total} files"),
                            "done": done,
                            "total": total,
                            "bytesScanned": bytes,
                        }));
                    },
                )
            })
            .await
            .map_err(|error| format!("the scan did not finish: {error}"))?;
            if cancel.load(Ordering::SeqCst) || scanned.cancelled {
                return Err("YARA scan cancelled".into());
            }
            stage(&mut managed, RunState::Normalizing)?;

            // ---- graph
            let run_id = managed.as_ref().expect("yara run exists").run().id.clone();
            let built = graph::build(&run_id, &scanned.matched, oxaudit_yara::YARA_X_VERSION)?;
            if !built.artifacts.is_empty() {
                managed
                    .as_mut()
                    .expect("yara run exists")
                    .append_artifacts(&built.artifacts)
                    .map_err(|error| error.to_string())?;
            }
            if !built.observations.is_empty() {
                managed
                    .as_mut()
                    .expect("yara run exists")
                    .append_observations(built.observations)
                    .map_err(|error| error.to_string())?;
            }
            stage(&mut managed, RunState::Assessing)?;

            if scanned.timed_out > 0 {
                let message = format!(
                    "{} file(s) timed out after {} s and were not fully evaluated.",
                    scanned.timed_out,
                    scan::FILE_TIMEOUT.as_secs()
                );
                warn(&mut managed, "yara_file_timeout", message.clone());
                incomplete_reasons.push(message);
            }
            if scanned.engine_errors > 0 {
                let message = format!(
                    "The YARA engine could not scan {} file(s); they are listed as skipped.",
                    scanned.engine_errors
                );
                warn(&mut managed, "yara_engine_error", message.clone());
                incomplete_reasons.push(message);
            }
            if built.dropped > 0 {
                let message = format!(
                    "More than {MAX_MATCH_ROWS} rule matches were found; {} were counted but not stored.",
                    built.dropped
                );
                warn(&mut managed, "yara_match_cap", message.clone());
                incomplete_reasons.push(message);
            }
            for entry in scanned.skipped.rows {
                skipped.push(entry.path, entry.reason);
            }
            skipped.dropped += scanned.skipped.dropped;
            if scanned.files_scanned == 0 {
                // An empty folder, or every file skipped: the rules were
                // never applied to anything, which is not "no rule matched".
                let message = format!(
                    "{rules_compiled} rule(s) compiled, but no file was scanned ({} file(s) skipped), so nothing was evaluated and the absence of matches means nothing.",
                    skipped.rows.len() as u64 + skipped.dropped
                );
                warn(&mut managed, "yara_nothing_scanned", message.clone());
                incomplete_reasons.push(message);
            }
            if skipped.dropped > 0 {
                notes.push(format!(
                    "{} more skipped files were counted but not listed.",
                    skipped.dropped
                ));
            }
            let incomplete = !incomplete_reasons.is_empty();
            notes.extend(incomplete_reasons.iter().cloned());

            let result = YaraScanResult {
                run_id: run_id.to_string(),
                target: target.to_string_lossy().into_owned(),
                state: if incomplete { "incomplete" } else { "completed" }.into(),
                files_scanned: scanned.files_scanned,
                bytes_scanned: scanned.bytes_scanned,
                matches: built.rows,
                matches_dropped: built.dropped,
                skipped: skipped.rows,
                skipped_dropped: skipped.dropped,
                packs: infos,
                rules_compiled,
                rules_skipped,
                rules_skipped_total,
                notes,
                incomplete_reasons,
                duration_ms: started.elapsed().as_millis() as u64,
            };
            stage(&mut managed, RunState::Persisting)?;
            service
                .repository()
                .canonical_save_projection(&run_id, "yara", 1, &result)
                .map_err(|error| error.to_string())?;
            if cancel.load(Ordering::SeqCst) {
                return Err("YARA scan cancelled".into());
            }
            if incomplete {
                managed
                    .take()
                    .expect("yara run exists")
                    .terminate(RunState::Incomplete, epoch_millis())
                    .map_err(|error| error.to_string())?;
            } else {
                managed
                    .as_mut()
                    .expect("yara run exists")
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
                        run.warning("yara_failed", error.clone());
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

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;
    use crate::findings::repository::FindingsRepository;
    use crate::findings::service::FindingsService;
    use crate::sigpacks::{PackKind, PackMetadata, SigPackStore};
    use oxaudit_domain::{ObservationKind, RunId, RunState};
    use sha2::Digest;

    const RULE_ALPHA: &str = r#"rule marker_alpha {
    meta:
        severity = "high"
    strings:
        $a = "OXAUDIT-FIXTURE-ALPHA"
    condition:
        $a
}
"#;
    const RULE_BETA: &str = r#"rule marker_beta {
    strings:
        $b = "OXAUDIT-FIXTURE-BETA"
    condition:
        $b
}
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

        fn install(&self, name: &str, rule_file: &Path) -> crate::sigpacks::InstalledSigPack {
            self.packs
                .store()
                .unwrap()
                .install(
                    PackKind::Yara,
                    rule_file,
                    &PackMetadata {
                        name: name.into(),
                        license: "Apache-2.0".into(),
                        ..Default::default()
                    },
                    "2026-11-18T00:00:00Z",
                )
                .unwrap()
        }

        async fn scan(&self, request: YaraScanRequest) -> Result<YaraScanResult, String> {
            self.scan_with(request, Arc::new(|_| {})).await
        }

        async fn scan_with(
            &self,
            request: YaraScanRequest,
            progress: Arc<dyn Fn(Value) + Send + Sync>,
        ) -> Result<YaraScanResult, String> {
            scan_yara_engine(
                &self.state.scan_work,
                &self.findings,
                &self.packs,
                &Quiet,
                progress,
                request,
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

    fn request(path: &Path) -> YaraScanRequest {
        YaraScanRequest {
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn matches_carry_offsets_hashes_and_a_canonical_graph() {
        let h = Harness::new();
        let rules = h.write("rules/alpha.yar", RULE_ALPHA);
        let hit = h.write("target/a/hit.bin", b"xx-OXAUDIT-FIXTURE-ALPHA-yy");
        h.write("target/b.txt", b"nothing to see here");
        let mut req = request(&h.dir.path().join("target"));
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![rules.to_string_lossy().into_owned()];
        let result = h.scan(req).await.unwrap();

        assert_eq!(result.state, "completed", "{:?}", result.notes);
        assert_eq!(result.files_scanned, 2);
        assert_eq!(result.matches.len(), 1);
        let row = &result.matches[0];
        assert_eq!(row.path, "a/hit.bin");
        assert_eq!(row.rule, "marker_alpha");
        assert_eq!(row.severity, "high");
        assert_eq!(row.pack, "adhoc");
        assert_eq!(row.rule_id, "adhoc/extra1/alpha.yar:marker_alpha");
        assert_eq!(row.strings.len(), 1);
        assert_eq!(row.strings[0].identifier, "$a");
        assert_eq!(row.strings[0].offset, 3);
        assert_eq!(row.strings[0].length, 21);
        assert_eq!(
            row.strings[0].excerpt_hex,
            hex::encode(b"OXAUDIT-FIXTURE-ALPHA")
        );
        assert_eq!(
            row.sha256,
            hex::encode(sha2::Sha256::digest(std::fs::read(&hit).unwrap()))
        );
        assert_eq!(result.rules_compiled, 1);

        // The run, projection and graph were stored.
        let run_id = RunId::parse(result.run_id.clone()).unwrap();
        assert_eq!(h.run_state(&result.run_id), RunState::Completed);
        let projection = h
            .repository()
            .canonical_load_projection(&run_id)
            .unwrap()
            .expect("projection is stored");
        assert_eq!(projection["matches"].as_array().unwrap().len(), 1);
        let (artifacts, _, observations) =
            h.repository().canonical_load_report_graph(&run_id).unwrap();
        assert_eq!(artifacts.len(), 1, "one artifact per matched file");
        assert_eq!(
            artifacts[0].content_sha256.as_deref(),
            Some(row.sha256.as_str())
        );
        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        assert_eq!(
            observation.observation.kind,
            ObservationKind::SignatureMatch
        );
        assert_eq!(observation.observation.detector_id, "oxaudit-yara");
        assert_eq!(
            observation.observation.rule_id.as_deref(),
            Some("adhoc/extra1/alpha.yar:marker_alpha")
        );
        match &observation.evidence[0].evidence {
            oxaudit_domain::Evidence::BinaryMatch(evidence) => {
                assert_eq!(evidence.offset, Some(3));
                assert_eq!(evidence.matcher_id, "$a");
                assert_eq!(evidence.encoding, "hex");
            }
            other => panic!("unexpected evidence {other:?}"),
        }
    }

    #[tokio::test]
    async fn excerpts_of_rules_that_report_secrets_are_masked_in_rows_projection_and_graph() {
        let h = Harness::new();
        let rules = h.write(
            "rules/secret.yar",
            r#"rule tagged : Credentials {
    strings:
        $k = "AKIAIOSFODNN7EXAMPLE"
    condition:
        $k
}
rule flagged {
    meta:
        sensitive = true
    strings:
        $p = "hunter2-password"
    condition:
        $p
}
rule short_secret : token {
    strings:
        $s = "pw=abc"
    condition:
        $s
}
"#,
        );
        h.write(
            "target/creds.txt",
            b"AKIAIOSFODNN7EXAMPLE hunter2-password pw=abc",
        );
        let mut req = request(&h.dir.path().join("target"));
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![rules.to_string_lossy().into_owned()];
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.matches.len(), 3, "{:?}", result.matches);
        let by_rule = |rule: &str| {
            result
                .matches
                .iter()
                .find(|row| row.rule == rule)
                .unwrap()
                .strings[0]
                .clone()
        };
        let tagged = by_rule("tagged");
        assert_eq!(tagged.excerpt_hex, hex::encode(b"AKIA"));
        assert!(tagged.excerpt_masked);
        assert_eq!(tagged.length, 20);
        assert_eq!(by_rule("flagged").excerpt_hex, hex::encode(b"hunt"));
        // Eight bytes or fewer: nothing of the value is kept.
        let short = by_rule("short_secret");
        assert_eq!(
            (short.excerpt_hex.as_str(), short.excerpt_masked),
            ("", true)
        );

        let run_id = RunId::parse(result.run_id.clone()).unwrap();
        let projection = h
            .repository()
            .canonical_load_projection(&run_id)
            .unwrap()
            .unwrap()
            .to_string();
        let (_, _, observations) = h.repository().canonical_load_report_graph(&run_id).unwrap();
        let graph = observations
            .iter()
            .map(|record| {
                format!(
                    "{}{}",
                    serde_json::to_string(&record.observation).unwrap(),
                    serde_json::to_string(&record.evidence).unwrap()
                )
            })
            .collect::<String>();
        for secret in [
            hex::encode(b"AKIAIOSFODNN7EXAMPLE"),
            hex::encode(b"hunter2-password"),
            hex::encode(b"pw=abc"),
        ] {
            assert!(!projection.contains(&secret), "projection leaks {secret}");
            assert!(!graph.contains(&secret), "graph leaks {secret}");
        }
        let evidence = observations
            .iter()
            .find(|o| o.observation.title == "tagged")
            .unwrap();
        match &evidence.evidence[0].evidence {
            oxaudit_domain::Evidence::BinaryMatch(binary) => {
                assert_eq!(binary.encoding, "masked-hex");
                assert_eq!(
                    binary.captured_value.as_deref(),
                    Some("414b4941\u{2026} (20 bytes)")
                );
            }
            other => panic!("unexpected evidence {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_empty_folder_or_every_file_skipped_is_incomplete_not_no_rule_matched() {
        let h = Harness::new();
        let rules = h.write("rules/alpha.yar", RULE_ALPHA);
        std::fs::create_dir_all(h.dir.path().join("empty")).unwrap();
        let mut req = request(&h.dir.path().join("empty"));
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![rules.to_string_lossy().into_owned()];
        let result = h.scan(req.clone()).await.unwrap();
        assert_eq!(result.files_scanned, 0);
        assert_eq!(result.state, "incomplete");
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|r| r.contains("1 rule(s) compiled, but no file was scanned")));
        assert_eq!(h.run_state(&result.run_id), RunState::Incomplete);

        // Every file over the size limit: listed as skipped, nothing scanned.
        h.write("big/a.bin", vec![0u8; 2 * 1024 * 1024]);
        req.path = h.dir.path().join("big").to_string_lossy().into_owned();
        req.max_file_size_mb = Some(1);
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.state, "incomplete");
        assert!(
            result
                .incomplete_reasons
                .iter()
                .any(|r| r.contains("(1 file(s) skipped)")),
            "{:?}",
            result.incomplete_reasons
        );
    }

    #[tokio::test]
    async fn installed_packs_are_applied_and_recorded_on_the_run() {
        let h = Harness::new();
        let pack = h.install("alpha", &h.write("rules/alpha.yar", RULE_ALPHA));
        h.write("target/hit.bin", b"OXAUDIT-FIXTURE-ALPHA");
        let result = h.scan(request(&h.dir.path().join("target"))).await.unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pack, pack.id);
        assert_eq!(result.matches[0].namespace, "alpha.yar");
        assert_eq!(result.packs.len(), 1);
        assert_eq!(result.packs[0].license, "Apache-2.0");
        assert_eq!(result.packs[0].rule_count, 1);
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
            vec![format!("yara:{}@{}", pack.id, &pack.content_sha256[..12])]
        );
    }

    #[tokio::test]
    async fn a_single_file_target_works() {
        let h = Harness::new();
        let rules = h.write("rules/alpha.yar", RULE_ALPHA);
        let file = h.write("lone.bin", b"OXAUDIT-FIXTURE-ALPHA");
        let mut req = request(&file);
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![rules.to_string_lossy().into_owned()];
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.matches[0].path, "lone.bin");
    }

    #[tokio::test]
    async fn oversized_unreadable_and_linked_files_are_listed_as_skipped() {
        let h = Harness::new();
        let rules = h.write("rules/alpha.yar", RULE_ALPHA);
        h.write("target/ok.bin", b"OXAUDIT-FIXTURE-ALPHA");
        h.write("target/big.bin", vec![b'a'; 1024 * 1024 + 1]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = h.write("target/locked.bin", b"OXAUDIT-FIXTURE-ALPHA");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            std::os::unix::fs::symlink(
                h.dir.path().join("rules"),
                h.dir.path().join("target/link"),
            )
            .unwrap();
        }
        let mut req = request(&h.dir.path().join("target"));
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![rules.to_string_lossy().into_owned()];
        req.max_file_size_mb = Some(1);
        let result = h.scan(req).await.unwrap();

        let reason = |path: &str| {
            result
                .skipped
                .iter()
                .find(|s| s.path == path)
                .map(|s| s.reason.clone())
        };
        assert!(reason("big.bin")
            .unwrap()
            .contains("larger than the 1 MiB limit"));
        assert_eq!(
            result.matches.len(),
            1 + usize::from(reason("locked.bin").is_none())
        );
        #[cfg(unix)]
        {
            assert!(reason("link").unwrap().contains("symbolic link"));
            // A process that can read mode-000 files (root) simply scans it.
            if let Some(reason) = reason("locked.bin") {
                assert!(reason.starts_with("unreadable"), "{reason}");
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                h.dir.path().join("target/locked.bin"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        // Skipped for size or readability is listed, and the run is complete.
        assert_eq!(result.state, "completed");
    }

    #[tokio::test]
    async fn cancelling_mid_scan_ends_cancelled_and_stores_no_projection() {
        let h = Harness::new();
        let rules = h.write("rules/alpha.yar", RULE_ALPHA);
        for i in 0..200 {
            h.write(&format!("target/f{i:03}.bin"), b"OXAUDIT-FIXTURE-ALPHA");
        }
        let mut req = request(&h.dir.path().join("target"));
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![rules.to_string_lossy().into_owned()];
        let state = h.state.clone();
        let cancel_on_first_progress: Arc<dyn Fn(Value) + Send + Sync> =
            Arc::new(move |_payload| {
                let _ = state
                    .scan_work
                    .cancel(None, &[crate::scan_work::WorkKind::Yara]);
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
    async fn zero_rules_fail_the_scan_instead_of_reporting_no_matches() {
        let h = Harness::new();
        h.write("target/x.bin", b"OXAUDIT-FIXTURE-ALPHA");
        let target = h.dir.path().join("target");

        let error = h.scan(request(&target)).await.unwrap_err();
        assert!(error.contains("No YARA rules"), "{error}");
        let snapshot = h.state.scan_work.snapshot().unwrap();
        assert_eq!(snapshot.recent[0].status, "failed");
        assert_eq!(
            h.run_state(&snapshot.recent[0].run_id.clone().unwrap()),
            RunState::Failed
        );

        // Rules that exist but all fail to compile are the same failure.
        let broken = h.write("rules/broken.yar", "rule broken { condition: $missing }");
        let mut req = request(&target);
        req.extra_rule_paths = vec![broken.to_string_lossy().into_owned()];
        let error = h.scan(req).await.unwrap_err();
        assert!(error.contains("did not compile"), "{error}");
    }

    #[tokio::test]
    async fn a_broken_rule_file_is_skipped_and_the_good_rules_still_scan() {
        let h = Harness::new();
        let dir = h.dir.path().join("rules");
        h.write("rules/alpha.yar", RULE_ALPHA);
        h.write("rules/broken.yar", "rule broken { condition: $missing }");
        h.write("target/x.bin", b"OXAUDIT-FIXTURE-ALPHA");
        let mut req = request(&h.dir.path().join("target"));
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![dir.to_string_lossy().into_owned()];
        let result = h.scan(req).await.unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.rules_skipped_total, 1);
        assert_eq!(result.rules_skipped[0].file, "extra1/broken.yar");
        assert_eq!(result.state, "completed");
        let run = h
            .repository()
            .canonical_load_run(&RunId::parse(result.run_id).unwrap())
            .unwrap()
            .unwrap();
        assert!(run.warnings.iter().any(|w| w.code == "yara_rules_skipped"));
    }

    #[tokio::test]
    async fn a_tampered_pack_makes_the_run_incomplete_with_a_warning() {
        let h = Harness::new();
        let good = h.install("good", &h.write("rules/alpha.yar", RULE_ALPHA));
        let bad = h.install("bad", &h.write("rules/beta.yar", RULE_BETA));
        h.write(
            "target/x.bin",
            b"OXAUDIT-FIXTURE-ALPHA OXAUDIT-FIXTURE-BETA",
        );
        std::fs::write(
            h.dir
                .path()
                .join("data/sigpacks/yara")
                .join(&bad.id)
                .join("beta.yar"),
            "rule evil { condition: true }",
        )
        .unwrap();
        let result = h.scan(request(&h.dir.path().join("target"))).await.unwrap();
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
        assert!(run.warnings.iter().any(|w| w.code == "yara_pack_skipped"));
        // Only the verified pack is recorded as applied.
        assert_eq!(run.rule_pack_ids.len(), 1);
    }

    #[tokio::test]
    async fn match_order_is_deterministic_and_the_target_is_left_untouched() {
        let h = Harness::new();
        let rules = h.write("rules/all.yar", format!("{RULE_ALPHA}\n{RULE_BETA}"));
        for i in 0..60 {
            let body = if i % 3 == 0 {
                "OXAUDIT-FIXTURE-ALPHA OXAUDIT-FIXTURE-BETA"
            } else {
                "OXAUDIT-FIXTURE-BETA"
            };
            h.write(&format!("target/d{}/f{i:02}.bin", i % 7), body);
        }
        let target = h.dir.path().join("target");
        let snapshot = |root: &Path| {
            let mut entries: Vec<(String, Vec<u8>, std::time::SystemTime)> =
                walkdir::WalkDir::new(root)
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_file())
                    .map(|e| {
                        (
                            e.path().to_string_lossy().into_owned(),
                            std::fs::read(e.path()).unwrap(),
                            e.metadata().unwrap().modified().unwrap(),
                        )
                    })
                    .collect();
            entries.sort();
            entries
        };
        let before = snapshot(&target);
        let mut req = request(&target);
        req.pack_ids = Some(vec![]);
        req.extra_rule_paths = vec![rules.to_string_lossy().into_owned()];
        let first = h.scan(req.clone()).await.unwrap();
        let second = h.scan(req).await.unwrap();
        assert_eq!(first.matches, second.matches);
        assert_eq!(first.matches.len(), 60 + 20);
        let paths: Vec<_> = first.matches.iter().map(|m| m.path.clone()).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "rows follow the walk order");
        assert_eq!(
            before,
            snapshot(&target),
            "scanning must not modify the target"
        );
    }

    #[tokio::test]
    async fn invalid_requests_are_rejected_before_any_work() {
        let h = Harness::new();
        let mut req = request(&h.dir.path().join("missing"));
        req.max_file_size_mb = Some(0);
        assert!(h.scan(req).await.unwrap_err().contains("maxFileSizeMb"));
        let req = request(&h.dir.path().join("missing"));
        assert!(h.scan(req).await.unwrap_err().contains("cannot resolve"));
    }
}

#[cfg(all(test, not(feature = "yara")))]
mod no_engine_tests {
    use super::*;

    struct Quiet;
    impl crate::findings::service::ScanEventSink for Quiet {
        fn emit(&self, _event: &str, _payload: Value) -> Result<(), CommandError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn scan_yara_without_the_engine_fails_instead_of_returning_an_empty_result() {
        let findings = FindingsState::available(FindingsService::new(
            crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
        ));
        let packs = SigPacksState::unavailable("none".into());
        let error = scan_yara_engine(
            &crate::scan_work::ScanWorkRegistry::default(),
            &findings,
            &packs,
            &Quiet,
            Arc::new(|_| {}),
            YaraScanRequest::default(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("no YARA engine"), "{error}");
    }
}
