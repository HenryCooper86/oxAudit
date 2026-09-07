import { ReviewChangesPanel } from "../features/source-scan/ReviewChangesPanel";
import { useReviewChanges } from "../features/source-scan/useReviewChanges";
import { acquireScan, cancelActiveScan, reconcileSourceRunSave, releaseScan, useScanWorkStore } from "../features/project-home/coordinator";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { Clipboard, RotateCcw, Search } from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
} from "react";
import { FindingDetail } from "../components/FindingDetail";
import { Button, Select } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { ToolPage } from "../components/workbench/ToolPage";
import { BulkReviewBar } from "../features/source-scan/BulkReviewBar";
import { FindingList } from "../features/source-scan/FindingList";
import { SourceProjectLoader } from "../features/source-scan/projectLoader";
import { ResultViewTabs } from "../features/source-scan/ResultViewTabs";
import {
  countViews,
  filterFindings,
  nextSelection,
  sanitizeExport,
} from "../features/source-scan/resultsModel";
import {
  EMPTY_SELECTION,
  pruneToVisible,
  selectAll,
  selectRange,
  toggle,
  type Selection,
} from "../features/source-scan/selectionModel";
import { RunHistory } from "../features/source-scan/RunHistory";
import { RunTimeline } from "../features/runs/RunTimeline";
import { SourceTargetPanel } from "../features/source-scan/SourceTargetPanel";
import type { ResultsQuery } from "../features/source-scan/types";
import { api } from "../lib/api";
import { resolveRuntimeProject } from "../lib/assistantSessions";
import { normalizeCommandError } from "../lib/commandError";
import { fmtBytes, fmtDuration } from "../lib/format";
import {
  buildSourceScanRequest,
  createSourceScanOptions,
  editSourceScanOption,
  hydrateSourceScanOptions,
  hydrateSourceScanOptionsFromProject,
  resolveSourceScanOptionsUnavailable,
  type SourceScanOptionKey,
  type SourceScanOptionValues,
} from "../lib/sourceScanOptions";
import { useAppStore, useToastStore } from "../lib/stores";
import type {
  CommandError,
  Finding,
  FindingScope,
  ProjectContext,
  RecentProject,
  ReviewRequest,
  ScanProgress,
  ScanRunDetail,
  ScanRunSummary,
  Severity,
} from "../lib/types";

const SEVERITIES: Array<Severity | "all"> = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const SCOPES: Array<FindingScope | "all"> = [
  "all",
  "production",
  "infrastructure",
  "test",
  "fixture",
  "generated",
  "vendored",
  "documentation",
  "unknown",
];

const DEFAULT_QUERY: ResultsQuery = {
  view: "open",
  category: "all",
  severity: "all",
  scope: "all",
  language: "all",
  search: "",
};

export function SourceScanPage(): JSX.Element {
  const settings = useAppStore((state) => state.settings);
  const settingsLoadError = useAppStore((state) => state.settingsLoadError);
  const addRecentScan = useAppStore((state) => state.addRecentScan);
  const publishActiveProject = useAppStore((state) => state.setActiveProject);
  const ownRuntimeUpdate = useRef(false);
  const pathEdited = useRef(false);
  const activeWork = useScanWorkStore(state => state.active);
  const setActiveProjectStore = useCallback((value: string | null) => {
    ownRuntimeUpdate.current = true;
    publishActiveProject(value);
    ownRuntimeUpdate.current = false;
  }, [publishActiveProject]);
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const push = useToastStore((state) => state.push);

  const [path, setPath] = useState(() => useAppStore.getState().activeProject ?? useAppStore.getState().selectedProject ?? "");
  const [scanOptions, setScanOptions] = useState(() =>
    createSourceScanOptions(settings?.scan ?? null),
  );
  const [project, setProject] = useState<ProjectContext | null>(null);
  const [recentProjects, setRecentProjects] = useState<RecentProject[]>([]);
  const [runs, setRuns] = useState<ScanRunSummary[]>([]);
  const [run, setRun] = useState<ScanRunDetail | null>(null);
  const [targetLoading, setTargetLoading] = useState(false);
  const [loadingRunId, setLoadingRunId] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [targetError, setTargetError] = useState<CommandError | null>(null);
  const [operationError, setOperationError] = useState<CommandError | null>(null);
  const [operationRetry, setOperationRetry] = useState<
    | { kind: "scan" }
    | { kind: "save" }
    | { kind: "loadRun"; runId: string }
    | null
  >(null);
  const [cancelled, setCancelled] = useState(false);
  const [retryingSave, setRetryingSave] = useState(false);
  const [savingReview, setSavingReview] = useState(false);
  const [reviewError, setReviewError] = useState<CommandError | null>(null);
  const [reviewAnnouncement, setReviewAnnouncement] = useState("");
  const [selectedFingerprint, setSelectedFingerprint] = useState<string | null>(null);
  const [query, setQuery] = useState<ResultsQuery>(DEFAULT_QUERY);
  const [recentUnavailable, setRecentUnavailable] = useState(false);
  const [loadVersion, setLoadVersion] = useState(0);
  const [handoffRunId, setHandoffRunId] = useState<string | undefined>();

  const cancellingRef = useRef(false);
  const runLoadGenerationRef = useRef(0);
  const loaderRef = useRef(new SourceProjectLoader(api));

  useEffect(() => {
    if (settings) {
      setScanOptions((current) => hydrateSourceScanOptions(current, settings.scan));
    } else if (settingsLoadError) {
      setScanOptions(resolveSourceScanOptionsUnavailable);
    }
  }, [settings, settingsLoadError]);

  useEffect(() => {
    let disposed = false;
    void api
      .listSourceProjects(12)
      .then((projects) => {
        if (!disposed) {
          setRecentProjects(projects);
          setRecentUnavailable(false);
        }
      })
      .catch(() => {
        if (!disposed) setRecentUnavailable(true);
      });
    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];
    const release = () => {
      for (const unlisten of unlisteners.splice(0)) unlisten();
    };
    const register = async () => {
      try {
        const progressUnlisten = await listen<ScanProgress>("scan://progress", (event) => {
          if (!disposed) setProgress(event.payload);
        });
        if (disposed) {
          progressUnlisten();
          return;
        }
        unlisteners.push(progressUnlisten);

        const doneUnlisten = await listen<ScanProgress>("scan://done", (event) => {
          if (!disposed) {
            setProgress((current) => ({ ...current, ...event.payload }));
          }
        });
        if (disposed) {
          doneUnlisten();
          return;
        }
        unlisteners.push(doneUnlisten);
      } catch {
        release();
        // The event bridge is unavailable in browser-only checks.
      }
    };
    void register();
    return () => {
      disposed = true;
      release();
    };
  }, []);

  useEffect(() => {
    if (!running) return;
    setPageStatus("source-scan", {
      label: "Scanning",
      tone: "running",
      detail: progress?.file,
    });
  }, [progress?.file, running, setPageStatus]);

  useEffect(() => {
    const candidate = path.trim();
    if (!candidate) {
      setTargetLoading(false);
      if (!pathEdited.current) return;
      void resolveRuntimeProject(null, api.setActiveProject).then((outcome) => {
        setActiveProjectStore(outcome.runtimePath);
      });
      return;
    }

    let disposed = false;
    const timer = window.setTimeout(() => {
      setTargetLoading(true);
      setTargetError(null);
      const check = useScanWorkStore.getState().check;
      const unsaved = check?.path === candidate && check.sourceResult?.runId === handoffRunId && check.sourceResult?.persistence.status === "notSaved" ? check.sourceResult : null;
      void loaderRef.current
        .load(candidate, unsaved ? undefined : handoffRunId)
        .then(async (loaded) => {
          if (disposed || !loaded) return;
          setProject(loaded.context);
          setRuns(loaded.runs);
          setRun(unsaved ?? loaded.run);
          setScanOptions((current) =>
            hydrateSourceScanOptionsFromProject(current, loaded.context.lastOptions),
          );

          const outcome = await resolveRuntimeProject(
            loaded.context.canonicalPath,
            api.setActiveProject,
          );
          if (disposed) return;
          setActiveProjectStore(outcome.runtimePath);
          useAppStore.getState().setSelectedProject(loaded.context.canonicalPath);
          if (outcome.warning) push("error", outcome.warning);
        })
        .catch((error) => {
          if (!disposed) setTargetError(normalizeCommandError(error));
        })
        .finally(() => {
          if (!disposed) setTargetLoading(false);
        });
    }, 350);

    return () => {
      disposed = true;
      window.clearTimeout(timer);
    };
  }, [handoffRunId, loadVersion, path, push, setActiveProjectStore]);

  useEffect(() => () => loaderRef.current.invalidate(), []);

  useEffect(() => {
    setReviewError(null);
  }, [selectedFingerprint]);

  const updateScanOption = <K extends SourceScanOptionKey>(
    key: K,
    value: SourceScanOptionValues[K],
  ) => {
    setScanOptions((current) => editSourceScanOption(current, key, value));
  };

  const changePath = useCallback(
    (nextPath: string) => {
      if (nextPath === path) return;
      pathEdited.current = true;
      loaderRef.current.invalidate();
      runLoadGenerationRef.current += 1;
      setHandoffRunId(undefined);
      setPath(nextPath);
      setProject(null);
      setRuns([]);
      setRun(null);
      setTargetError(null);
      setOperationError(null);
      setOperationRetry(null);
      setCancelled(false);
      setSelectedFingerprint(null);
      setQuery(DEFAULT_QUERY);
      clearPageStatus("source-scan");
    },
    [clearPageStatus, path],
  );

  useEffect(() => {
    const applyHandoff = () => {
      const handoff = useAppStore.getState().projectHandoff;
      if (handoff?.page === "source-scan") {
        runLoadGenerationRef.current += 1;
        changePath(handoff.path);
        setHandoffRunId(handoff.runId);
        setLoadVersion(value => value + 1);
        useAppStore.setState({ projectHandoff: null });
      }
    };
    applyHandoff();
    return useAppStore.subscribe((state, previous) => {
      if (state.projectHandoff !== previous.projectHandoff) applyHandoff();
      else if (!ownRuntimeUpdate.current && state.activeProject !== previous.activeProject && state.activeProject) changePath(state.activeProject);
    });
  }, [changePath]);

  const refreshMetadata = useCallback(async (projectId: string, expectedGeneration = runLoadGenerationRef.current) => {
    const [context, nextRuns, nextRecent] = await Promise.all([
      api.inspectSourceProject(project?.canonicalPath ?? path),
      api.listSourceRuns(projectId, 50),
      api.listSourceProjects(12),
    ]);
    if (expectedGeneration !== runLoadGenerationRef.current) return;
    setProject(context);
    setRuns(nextRuns);
    setRecentProjects(nextRecent);
    setRecentUnavailable(false);
  }, [path, project?.canonicalPath]);

  const runScan = async (ignoreInvalidPolicy = false) => {
    const target = project?.canonicalPath ?? path.trim();
    const values = scanOptions.values;
    if (
      !project ||
      !target ||
      running ||
      !scanOptions.resolved ||
      (!values.scanSecrets && !values.scanVulnerabilities) ||
      (project.policy.status === "invalid" && !ignoreInvalidPolicy)
    ) {
      return;
    }

    const ownership = acquireScan("source", target, "Scanning source");
    if (ownership === null) return;
    const runGeneration = runLoadGenerationRef.current;
    setRunning(true);
    cancellingRef.current = false;
    setCancelling(false);
    setOperationError(null);
    setOperationRetry(null);
    setCancelled(false);
    setProgress({ phase: "walking" });
    try {
      const runtime = await resolveRuntimeProject(target, api.setActiveProject);
      setActiveProjectStore(runtime.runtimePath);
      if (runtime.runtimePath !== target) {
        throw new Error(runtime.warning ?? "The selected project is unavailable.");
      }

      if (runGeneration !== runLoadGenerationRef.current) return;
      if (useScanWorkStore.getState().active?.cancelling) {
        setCancelled(true);
        setPageStatus("source-scan", { label: "Scan cancelled", tone: "neutral" });
        return;
      }
      const result = await api.scanProject(
        buildSourceScanRequest(target, scanOptions, ignoreInvalidPolicy),
      );
      if (runGeneration !== runLoadGenerationRef.current) return;
      setRun(result);
      setSelectedFingerprint((current) =>
        current && result.findings.some((finding) => finding.fingerprint === current)
          ? current
          : null,
      );
      setPageStatus("source-scan", {
        label: result.persistence.status === "saved" ? "Scan complete" : "Scan complete, not saved",
        tone: result.persistence.status === "saved" ? "success" : "error",
        detail: `${result.summary.totalFindings} findings`,
      });

      if (result.status === "completed" && result.persistence.status === "saved") {
        addRecentScan({
          id: result.runId,
          kind: "source",
          path: target,
          at: result.completedAt ?? new Date().toISOString(),
          findings: result.summary.totalFindings,
          critical: result.summary.critical,
          high: result.summary.high,
        });
      }
      push(
        result.persistence.status === "saved" ? "success" : "info",
        result.persistence.status === "saved"
          ? `Scan complete — ${result.summary.totalFindings} findings in ${fmtDuration(result.summary.durationMs)}`
          : `Scan complete — ${result.summary.totalFindings} findings are available, but the run was not saved.`,
      );

      try {
        await refreshMetadata(result.projectId, runGeneration);
      } catch {
        push("info", "The scan completed, but project history could not be refreshed.");
      }
    } catch (error) {
      if (runGeneration !== runLoadGenerationRef.current) return;
      const normalized = normalizeCommandError(error);
      if (normalized.code === "scanCancelled") {
        setCancelled(true);
        setPageStatus("source-scan", { label: "Scan cancelled", tone: "neutral" });
        push("info", "Scan cancelled");
      } else {
        setOperationError(normalized);
        setOperationRetry(normalized.retryable ? { kind: "scan" } : null);
        setPageStatus("source-scan", { label: "Scan failed", tone: "error" });
        push("error", normalized.message);
      }
    } finally {
      releaseScan(ownership);
      setRunning(false);
      cancellingRef.current = false;
      setCancelling(false);
      setProgress(null);
    }
  };

  const cancel = async () => {
    if (cancellingRef.current) return;
    cancellingRef.current = true;
    setCancelling(true);
    try {
      await cancelActiveScan();
      if (!useScanWorkStore.getState().active?.cancelling) throw new Error("Cancellation unavailable");
      push("info", "Cancelling scan…");
    } catch {
      cancellingRef.current = false;
      setCancelling(false);
      push("error", "The scan could not be cancelled.");
    }
  };

  const loadRun = async (runId: string) => {
    if (runId === run?.runId) return;
    const generation = ++runLoadGenerationRef.current;
    setLoadingRunId(runId);
    setOperationError(null);
    setOperationRetry(null);
    try {
      const loaded = await api.loadSourceRun(runId);
      if (generation !== runLoadGenerationRef.current) return;
      setRun(loaded);
      setSelectedFingerprint((current) =>
        current && loaded.findings.some((finding) => finding.fingerprint === current)
          ? current
          : null,
      );
    } catch (error) {
      if (generation === runLoadGenerationRef.current) {
        const normalized = normalizeCommandError(error);
        setOperationError(normalized);
        setOperationRetry(normalized.retryable ? { kind: "loadRun", runId } : null);
      }
    } finally {
      if (generation === runLoadGenerationRef.current) setLoadingRunId(null);
    }
  };

  const retrySave = async () => {
    if (!run || run.persistence.status !== "notSaved" || retryingSave) return;
    const requestedRun = run;
    const requestedPath = project?.canonicalPath ?? run.summary.path;
    const generation = runLoadGenerationRef.current;
    setRetryingSave(true);
    setOperationError(null);
    setOperationRetry(null);
    try {
      const saved = await api.retrySourceRunSave(run.persistence.retryToken);
      if (saved.projectId !== requestedRun.projectId || saved.runId !== requestedRun.runId) {
        throw new Error("The save response belongs to a different source run.");
      }
      if (saved.persistence.status !== "saved") throw new Error("The source run was not saved. Retry saving the current receipt.");
      reconcileSourceRunSave(requestedPath, saved);
      if (generation !== runLoadGenerationRef.current) return;
      setRun(saved);
      push("success", "The scan run was saved to project history.");
      try {
        await refreshMetadata(saved.projectId, generation);
      } catch {
        push("info", "The run was saved, but project history could not be refreshed.");
      }
    } catch (error) {
      if (generation !== runLoadGenerationRef.current) return;
      const normalized = normalizeCommandError(error);
      setOperationError(normalized);
      setOperationRetry(normalized.retryable ? { kind: "save" } : null);
    } finally {
      setRetryingSave(false);
    }
  };

  const saveReview = async (request: ReviewRequest) => {
    if (!run || savingReview) return;
    setSavingReview(true);
    setReviewError(null);
    setOperationError(null);
    setOperationRetry(null);
    try {
      await api.saveFindingReview(request);
      push("success", "Review saved.");
      let refreshed: ScanRunDetail;
      try {
        refreshed = await api.loadSourceRun(run.runId);
      } catch (error) {
        const normalized = normalizeCommandError(error);
        setOperationError({
          ...normalized,
          message: "The review was saved, but refreshed results could not be loaded.",
        });
        setOperationRetry(
          normalized.retryable ? { kind: "loadRun", runId: run.runId } : null,
        );
        setReviewAnnouncement("Review saved, but refreshed results could not be loaded.");
        return;
      }

      setRun(refreshed);
      setSelectedFingerprint(request.fingerprint);
      setReviewAnnouncement("Review saved and finding views refreshed.");
      try {
        await refreshMetadata(refreshed.projectId);
      } catch {
        push("info", "The review was saved, but project totals could not be refreshed.");
      }
    } catch (error) {
      setReviewError(normalizeCommandError(error));
    } finally {
      setSavingReview(false);
    }
  };

  const reviewChanges = useReviewChanges(project?.canonicalPath ?? "", run);
  const findings = reviewChanges.findings;
  const counts = useMemo(() => countViews(findings), [findings]);
  const filtered = useMemo(
    () => filterFindings(findings, { ...query, newOnly: query.newOnly && reviewChanges.hasBaseline }),
    [findings, query, reviewChanges.hasBaseline],
  );
  const effectiveSelection = nextSelection(filtered, selectedFingerprint);
  const [selection, setSelection] = useState<Selection>(EMPTY_SELECTION);
  const [bulkSaving, setBulkSaving] = useState(false);
  const [bulkFailures, setBulkFailures] = useState(0);
  // The anchor for shift-extension is the last row toggled, not the last row
  // viewed — extending from something the reviewer merely looked at would
  // select a range they never indicated.
  const bulkAnchor = useRef<string | null>(null);

  // Filters are how a reviewer says "this class". When they change, anything no
  // longer on screen leaves the selection: applying a decision to findings the
  // reviewer can no longer see is the failure this prevents.
  useEffect(() => {
    setSelection((current) =>
      current.size === 0 ? current : pruneToVisible(current, filtered),
    );
  }, [filtered]);

  const toggleSelect = (fingerprint: string, extend: boolean) => {
    setSelection((current) => {
      const anchor = bulkAnchor.current;
      if (extend && anchor) return selectRange(current, filtered, anchor, fingerprint);
      return toggle(current, fingerprint);
    });
    bulkAnchor.current = fingerprint;
  };

  const applyBulkReview = async (requests: ReviewRequest[]) => {
    if (!run || bulkSaving) return;
    setBulkSaving(true);
    setBulkFailures(0);
    try {
      const outcome = await api.saveFindingReviews(requests);
      setBulkFailures(outcome.failures.length);
      // The selection is cleared only on a clean run. After a partial one the
      // reviewer keeps their selection so they can see what they acted on.
      if (outcome.failures.length === 0) {
        setSelection(EMPTY_SELECTION);
        bulkAnchor.current = null;
        push("success", `${outcome.recorded.length} reviews recorded.`);
      } else {
        push(
          "info",
          `${outcome.recorded.length} recorded, ${outcome.failures.length} not applied.`,
        );
      }
      const refreshed = await api.loadSourceRun(run.runId);
      setRun(refreshed);
      setReviewAnnouncement(`${outcome.recorded.length} reviews recorded.`);
    } catch (error) {
      setReviewError(normalizeCommandError(error));
    } finally {
      setBulkSaving(false);
    }
  };
  const selectedFinding =
    filtered.find((finding) => finding.fingerprint === effectiveSelection) ?? null;
  const hasExplicitSelection =
    selectedFingerprint !== null && selectedFingerprint === effectiveSelection;
  const languages = useMemo(() => {
    const values = new Set<string>();
    for (const finding of findings) {
      if (finding.language) values.add(finding.language);
    }
    return Array.from(values).sort();
  }, [findings]);

  const copyJson = async () => {
    if (!run) return;
    const report = {
      tool: "oxAudit",
      exportedAt: new Date().toISOString(),
      projectId: run.projectId,
      runId: run.runId,
      baselineRunId: run.baselineRunId,
      status: run.status,
      summary: run.summary,
      findings: sanitizeExport(run.findings),
    };
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      push("success", "Redacted scan report copied to clipboard.");
    } catch {
      push("error", "Clipboard unavailable.");
    }
  };

  const copyFinding = async (finding: Finding) => {
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(
        JSON.stringify(sanitizeExport([finding])[0], null, 2),
      );
      push("success", "Redacted finding copied to clipboard.");
    } catch {
      push("error", "Clipboard unavailable.");
    }
  };

  const openFile = (finding: Finding) => {
    if (!run) return;
    void api.openScanFinding(run.summary.path, finding.filePath).catch(() => {
      push("error", "The finding file could not be opened.");
    });
  };

  const clearFilters = () => {
    reviewChanges.setPathMode("all");
    setQuery((current) => ({ ...DEFAULT_QUERY, view: current.view }));
    setSelectedFingerprint(null);
  };

  const scanUnavailable =
    !scanOptions.values.scanSecrets && !scanOptions.values.scanVulnerabilities;

  return (
    <ToolPage
      title="Source Scan"
      description="Scan a local project, compare durable runs, and record review decisions without exposing secret material."
      context={project ? <span className="font-mono text-[10px] text-text-muted">{project.displayName}</span> : undefined}
    >
      <SourceTargetPanel
        path={path}
        recentProjects={recentProjects}
        project={project}
        options={scanOptions}
        running={running}
        blocked={Boolean(activeWork)}
        cancelling={cancelling}
        dropping={false}
        progress={progress}
        onPathChange={changePath}
        onOptionChange={updateScanOption}
        onRun={(ignoreInvalidPolicy) => void runScan(ignoreInvalidPolicy)}
        onCancel={() => void cancel()}
      />
      {project && <ReviewChangesPanel review={reviewChanges} run={run} runs={runs} newOnly={Boolean(query.newOnly)} onNewOnly={newOnly => setQuery(current => ({ ...current, newOnly }))} />}
      <RunTimeline
        active={!running && run ? "completed" : !running ? "discovering" : progress?.phase === "walking" ? "discovering" : progress?.phase === "scanning" ? "detecting" : "persisting"}
        running={running}
        hasCompletedResult={Boolean(run)}
      />

      {!scanOptions.resolved && (
        <InlineState tone="running" compact title="Loading scan defaults" description="Run scan becomes available after local settings finish loading." />
      )}
      {settingsLoadError && settings === null && scanOptions.resolved && (
        <InlineState tone="unavailable" compact title="Using fallback scan defaults" description="Local settings could not be loaded. The displayed controls are the exact options that will be submitted." />
      )}
      {recentUnavailable && (
        <InlineState tone="unavailable" compact title="Recent targets are unavailable" description="You can still inspect a folder and run a scan." />
      )}
      {targetLoading && (
        <InlineState tone="running" compact title="Inspecting project" description="Loading policy status, saved options, and the latest completed run." />
      )}
      {targetError && !targetLoading && (
        <OperationError
          error={targetError}
          title="The project could not be inspected"
          onRetry={targetError.retryable ? () => setLoadVersion((value) => value + 1) : undefined}
        />
      )}
      {operationError && !running && (
        <OperationError
          error={operationError}
          title="The operation could not be completed"
          onRetry={operationRetry ? () => {
            if (operationRetry.kind === "scan") void runScan(false);
            if (operationRetry.kind === "save") void retrySave();
            if (operationRetry.kind === "loadRun") void loadRun(operationRetry.runId);
          } : undefined}
        />
      )}
      {cancelled && !running && <ScanCancelled hasPreviousResults={Boolean(run)} />}

      {project && (
        <div className="grid items-start gap-4 min-[980px]:grid-cols-[minmax(0,1fr)_20rem]">
          {run ? (
            <section aria-label="Scan summary" className="grid grid-cols-2 overflow-hidden rounded-sm border border-border bg-surface-secondary min-[700px]:grid-cols-5">
              <SummaryMetric label="Files" value={run.summary.filesScanned.toLocaleString()} />
              <SummaryMetric label="Secrets" value={run.summary.secretsFound.toLocaleString()} />
              <SummaryMetric label="Vulnerabilities" value={run.summary.vulnerabilitiesFound.toLocaleString()} />
              <SummaryMetric label="Critical / High" value={`${run.summary.critical} / ${run.summary.high}`} />
              <SummaryMetric label="Scanned" value={`${fmtBytes(run.summary.bytesScanned)} · ${fmtDuration(run.summary.durationMs)}`} />
            </section>
          ) : (
            <InlineState tone="idle" title="Project ready" description="No completed source scan has been saved for this project yet." />
          )}
          <RunHistory
            runs={runs}
            selectedRunId={run?.runId ?? null}
            loadingRunId={loadingRunId}
            onSelect={(runId) => void loadRun(runId)}
          />
        </div>
      )}

      {run?.persistence.status === "notSaved" && (
        <InlineState
          tone="unavailable"
          title="Scan complete, but history was not saved"
          description="The results remain available in this window. Retry before closing oxAudit if you want this run in project history."
          action={
            <Button type="button" onClick={() => void retrySave()} variant="primary" size="md" disabled={retryingSave}>
              <RotateCcw size={13} aria-hidden="true" />
              {retryingSave ? "Saving…" : "Retry save"}
            </Button>
          }
        />
      )}

      {run?.maintenanceWarning && (
        <InlineState tone="unavailable" compact title="History maintenance needs attention" description={run.maintenanceWarning} />
      )}

      {run && reviewChanges.allFindings.length > 0 && (
        <section aria-label="Source scan results" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <ResultViewTabs
            value={query.view}
            counts={counts}
            onChange={(view) => {
              setQuery((current) => ({ ...current, view }));
              setSelectedFingerprint(null);
            }}
          />
          <ResultsToolbar
            countLabel={`${filtered.length} in this view · ${reviewChanges.allFindings.length} total`}
            filters={
              <>
                <Select aria-label="Finding category" value={query.category} onChange={(event) => setQuery((current) => ({ ...current, category: event.target.value as ResultsQuery["category"] }))} variant="compact">
                  <option value="all">All categories</option>
                  <option value="secret">Secrets</option>
                  <option value="vulnerability">Vulnerabilities</option>
                </Select>
                <Select aria-label="Finding severity" value={query.severity} onChange={(event) => setQuery((current) => ({ ...current, severity: event.target.value as ResultsQuery["severity"] }))} variant="compact">
                  {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity === "all" ? "All severities" : severity}</option>)}
                </Select>
                <Select aria-label="Finding scope" value={query.scope} onChange={(event) => setQuery((current) => ({ ...current, scope: event.target.value as ResultsQuery["scope"] }))} variant="compact">
                  {SCOPES.map((scope) => <option key={scope} value={scope}>{scope === "all" ? "All scopes" : scope}</option>)}
                </Select>
                <Select aria-label="Finding language" value={query.language} onChange={(event) => setQuery((current) => ({ ...current, language: event.target.value }))} variant="compact">
                  <option value="all">All languages</option>
                  {languages.map((language) => <option key={language} value={language}>{language}</option>)}
                </Select>
              </>
            }
            search={
              <label className="relative min-w-0">
                <span className="sr-only">Search findings</span>
                <Search size={13} aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                <input value={query.search} onChange={(event) => setQuery((current) => ({ ...current, search: event.target.value }))} placeholder="Search findings…" className="w-44 rounded-sm border border-border bg-surface-primary py-1.5 pl-8 pr-2 text-[12px] text-text-primary placeholder:text-text-muted" />
              </label>
            }
            actions={
              <Button type="button" onClick={() => void copyJson()} variant="outline" size="md">
                <Clipboard size={13} aria-hidden="true" />
                Copy JSON
              </Button>
            }
          />

          <div id="source-results-panel" role="tabpanel" aria-labelledby={`source-results-tab-${query.view}`}>
            {filtered.length > 0 ? (
              <SplitWorkspace
                panelId="source-findings"
                listLabel="Findings"
                detailLabel="Finding detail"
                hasSelection={hasExplicitSelection}
                onBackToList={() => setSelectedFingerprint(null)}
                list={
                  <>
                    <FindingList
                      findings={filtered}
                      selectedFingerprint={effectiveSelection}
                      onSelect={setSelectedFingerprint}
                      selection={selection}
                      onToggleSelect={toggleSelect}
                    />
                    <BulkReviewBar
                      projectId={run.projectId}
                      visible={filtered}
                      selection={selection}
                      saving={bulkSaving}
                      failures={bulkFailures}
                      onClear={() => {
                        setSelection(EMPTY_SELECTION);
                        bulkAnchor.current = null;
                        setBulkFailures(0);
                      }}
                      onSelectAll={() => setSelection(selectAll(filtered))}
                      onApply={applyBulkReview}
                    />
                  </>
                }
                detail={selectedFinding ? (
                  <FindingDetail
                    projectId={run.projectId}
                    finding={selectedFinding}
                    savingReview={savingReview}
                    reviewError={reviewError}
                    onSaveReview={saveReview}
                    onCopy={(finding) => void copyFinding(finding)}
                    onOpenFile={openFile}
                  />
                ) : <InlineState tone="empty" title="Select a finding" compact />}
              />
            ) : (
              <InlineState
                tone="empty"
                title="No findings match this view and its filters"
                description="Change the Git path or baseline filter, widen category, severity, scope, or language, or clear all filters."
                action={<Button type="button" onClick={clearFilters} variant="outline" size="md">Clear filters</Button>}
              />
            )}
          </div>
        </section>
      )}

      {run && reviewChanges.allFindings.length === 0 && (
        <InlineState
          tone="empty"
          title="No findings detected"
          description={`No findings were detected in ${run.summary.filesScanned} scanned files; ${run.summary.filesSkipped} files were skipped. This does not establish that unscanned files are safe.`}
          action={<Button type="button" onClick={() => void copyJson()} variant="outline" size="md"><Clipboard size={13} aria-hidden="true" />Copy JSON</Button>}
        />
      )}

      {!run && !project && !targetLoading && !targetError && !scanUnavailable && (
        <InlineState tone="idle" title="Choose a project to begin" description="Browse, paste a path, or drop a project folder. oxAudit will restore its latest completed run automatically." />
      )}
      {!run && running && !progress && (
        <InlineState tone="running" title="Starting source scan" description="Preparing the selected project." />
      )}

      <p className="sr-only" aria-live="polite">{reviewAnnouncement}</p>
    </ToolPage>
  );
}

function SummaryMetric({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="min-w-0 border-b border-r border-border px-3 py-2.5 last:border-r-0 min-[700px]:border-b-0">
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">{label}</p>
      <p className="mt-1 truncate text-[13px] font-medium tabular-nums text-text-primary" title={value}>{value}</p>
    </div>
  );
}

function OperationError({
  error,
  title,
  onRetry,
}: {
  error: CommandError;
  title: string;
  onRetry?: () => void;
}): JSX.Element {
  return (
    <InlineState
      tone="error"
      compact
      title={title}
      description={error.message}
      action={
        <>
          {onRetry && <Button type="button" onClick={onRetry} variant="danger" size="md">Retry</Button>}
          {error.detail && (
            <details className="text-[11px] text-text-muted">
              <summary className="cursor-pointer hover:text-text-primary">Details</summary>
              <p className="selectable mt-2 max-w-prose whitespace-pre-wrap rounded-sm border border-border bg-surface-primary p-2 font-mono text-[11px] text-text-muted">{error.detail}</p>
            </details>
          )}
        </>
      }
    />
  );
}

function ScanCancelled({ hasPreviousResults }: { hasPreviousResults: boolean }): JSX.Element {
  return (
    <InlineState
      tone="idle"
      compact
      title="Scan cancelled"
      description={hasPreviousResults ? "The previous completed results are still available." : "No results were changed. You can run the scan again when ready."}
    />
  );
}
