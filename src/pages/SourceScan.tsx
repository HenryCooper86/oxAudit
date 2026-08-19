import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { Ban, Clipboard, FileCode2, KeyRound, Play, Search } from "lucide-react";
import { FindingDetail } from "../components/FindingDetail";
import { FolderPicker } from "../components/FolderPicker";
import { ProgressBar } from "../components/ProgressBar";
import { SeverityBadge } from "../components/SeverityBadge";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { resolveRuntimeProject } from "../lib/assistantSessions";
import { fmtBytes, fmtDuration } from "../lib/format";
import {
  buildSourceScanRequest,
  createSourceScanOptions,
  editSourceScanOption,
  hydrateSourceScanOptions,
  resolveSourceScanOptionsUnavailable,
  type SourceScanOptionKey,
  type SourceScanOptionValues,
} from "../lib/sourceScanOptions";
import { useAppStore, useToastStore } from "../lib/stores";
import type { Finding, ScanProgress, ScanResult, Severity } from "../lib/types";
import { Button, Select, Switch } from "../components/ui";

const SEVERITIES: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];

export function SourceScanPage() {
  const settings = useAppStore((state) => state.settings);
  const settingsLoadError = useAppStore((state) => state.settingsLoadError);
  const addRecentScan = useAppStore((state) => state.addRecentScan);
  const setActiveProjectStore = useAppStore((state) => state.setActiveProject);
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const push = useToastStore((state) => state.push);

  const [path, setPath] = useState("");
  const [scanOptions, setScanOptions] = useState(() =>
    createSourceScanOptions(settings?.scan ?? null),
  );
  const {
    scanSecrets,
    scanVulnerabilities: scanVulns,
    includeGit,
    followSymlinks,
    maxFileSizeKb: maxSizeKb,
  } = scanOptions.values;

  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const [tab, setTab] = useState<"all" | "secret" | "vulnerability">("all");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [langFilter, setLangFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const cancellingRef = useRef(false);
  const pathRequestRef = useRef(0);

  useEffect(() => {
    if (settings) {
      setScanOptions((current) =>
        hydrateSourceScanOptions(current, settings.scan),
      );
    } else if (settingsLoadError) {
      setScanOptions(resolveSourceScanOptionsUnavailable);
    }
  }, [settings, settingsLoadError]);

  const updateScanOption = <K extends SourceScanOptionKey>(
    key: K,
    value: SourceScanOptionValues[K],
  ) => {
    setScanOptions((current) => editSourceScanOption(current, key, value));
  };

  useEffect(() => {
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];
    const releaseListeners = () => {
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
          if (!disposed) setProgress((current) => ({ ...current, ...event.payload }));
        });
        if (disposed) {
          doneUnlisten();
          return;
        }
        unlisteners.push(doneUnlisten);
      } catch {
        releaseListeners();
        // The event bridge is unavailable when the UI is exercised in a browser.
      }
    };

    void register();
    return () => {
      disposed = true;
      releaseListeners();
    };
  }, []);

  useEffect(() => {
    if (!running) return;
    setPageStatus("source-scan", { label: "Scanning", tone: "running", detail: progress?.file });
  }, [progress?.file, running, setPageStatus]);

  const filtered = useMemo(() => {
    if (!result) return [];
    const query = search.trim().toLowerCase();
    return result.findings.filter((finding) => {
      if (tab !== "all" && finding.category !== tab) return false;
      if (sevFilter !== "all" && finding.severity !== sevFilter) return false;
      if (langFilter !== "all" && finding.language !== langFilter) return false;
      if (
        query &&
        !`${finding.ruleName} ${finding.filePath} ${finding.matchText}`.toLowerCase().includes(query)
      ) {
        return false;
      }
      return true;
    });
  }, [langFilter, result, search, sevFilter, tab]);

  const selectedFinding = filtered.find((finding) => finding.id === selectedFindingId) ?? filtered[0] ?? null;
  const hasExplicitSelection =
    selectedFindingId !== null && selectedFinding?.id === selectedFindingId;

  const languages = useMemo(() => {
    if (!result) return [];
    const found = new Set<string>();
    for (const finding of result.findings) {
      if (finding.language) found.add(finding.language);
    }
    return ["all", ...Array.from(found).sort()];
  }, [result]);

  const resetResultState = () => {
    setResult(null);
    setError(null);
    setCancelled(false);
    setTab("all");
    setSevFilter("all");
    setLangFilter("all");
    setSearch("");
    setSelectedFindingId(null);
    clearPageStatus("source-scan");
  };

  const changePath = (nextPath: string) => {
    if (nextPath === path) return;
    const requestId = ++pathRequestRef.current;
    setPath(nextPath);
    resetResultState();
    void resolveRuntimeProject(nextPath || null, api.setActiveProject).then((outcome) => {
      setActiveProjectStore(outcome.runtimePath);
      if (
        requestId === pathRequestRef.current &&
        outcome.unavailablePath === nextPath &&
        outcome.warning
      ) {
        push("error", outcome.warning);
      }
    });
  };

  const run = async () => {
    if (
      !path ||
      running ||
      !scanOptions.resolved ||
      (!scanSecrets && !scanVulns)
    ) {
      return;
    }
    setRunning(true);
    cancellingRef.current = false;
    setCancelling(false);
    setError(null);
    setCancelled(false);
    setProgress({ phase: "walking" });
    const requestId = ++pathRequestRef.current;
    const requestedPath = path;
    try {
      const runtime = await resolveRuntimeProject(
        requestedPath,
        api.setActiveProject,
      );
      setActiveProjectStore(runtime.runtimePath);
      if (
        requestId !== pathRequestRef.current ||
        runtime.runtimePath !== requestedPath
      ) {
        return;
      }
      const res = await api.scanProject(
        buildSourceScanRequest(requestedPath, scanOptions),
      );
      setResult(res);
      setSelectedFindingId(null);
      setPageStatus("source-scan", {
        label: "Scan complete",
        tone: "success",
        detail: `${res.summary.totalFindings} findings`,
      });
      addRecentScan({
        id: `${Date.now()}`,
        kind: "source",
        path,
        at: new Date().toISOString(),
        findings: res.summary.totalFindings,
        critical: res.summary.critical,
        high: res.summary.high,
      });
      push(
        "success",
        `Scan complete — ${res.summary.totalFindings} findings in ${fmtDuration(res.summary.durationMs)}`,
      );
    } catch (scanError) {
      const detail = String(scanError);
      if (detail.toLowerCase().includes("scan cancelled")) {
        setError(null);
        setCancelled(true);
        setPageStatus("source-scan", { label: "Scan cancelled", tone: "neutral" });
        push("info", "Scan cancelled");
      } else {
        setError(detail);
        setPageStatus("source-scan", { label: "Scan failed", tone: "error" });
        push("error", "The selected folder could not be scanned");
      }
    } finally {
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
      await api.cancelScan();
      push("info", "Cancelling scan…");
    } catch {
      cancellingRef.current = false;
      setCancelling(false);
      push("error", "The scan could not be cancelled");
    }
  };

  const copyJson = async () => {
    if (!result) return;
    const report = {
      tool: "oxAudit",
      version: "0.1.0",
      exportedAt: new Date().toISOString(),
      summary: result.summary,
      findings: result.findings,
    };
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      push("success", "Scan report copied to clipboard (JSON)");
    } catch {
      push("error", "Clipboard unavailable");
    }
  };

  const copyFinding = async (finding: Finding) => {
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
      push("success", "Finding copied to clipboard");
    } catch {
      push("error", "Clipboard unavailable");
    }
  };

  const openFile = (finding: Finding) => {
    if (!result) return;
    void api
      .openScanFinding(result.summary.path, finding.filePath)
      .catch((openError) => {
        push("error", `The finding file could not be opened: ${String(openError)}`);
      });
  };

  const scanUnavailable = !scanSecrets && !scanVulns;
  const progressLabel =
    progress?.phase === "walking"
      ? "Walking directory tree…"
      : "Scanning files for secrets and vulnerable patterns…";

  return (
    <ToolPage
      title="Source Scan"
      description="Scan a local project for exposed secrets and vulnerable source patterns."
    >
      <TargetBar
        primary={
          <>
            {running && (
              <Button
                type="button"
                onClick={cancel}
                disabled={cancelling}
                variant="danger"
                size="md"
              >
                <Ban size={13} aria-hidden="true" />
                {cancelling ? "Cancelling…" : "Cancel"}
              </Button>
            )}
            <Button
              type="button"
              onClick={run}
              disabled={!path || running || !scanOptions.resolved || scanUnavailable}
              variant="primary"
              size="md"
            >
              <Play size={13} aria-hidden="true" />
              {running ? "Scanning…" : "Run scan"}
            </Button>
          </>
        }
        secondary={
          <>
            <details>
              <summary className="w-fit cursor-pointer text-[12px] font-medium text-text-secondary hover:text-text-primary">
                Advanced scan settings
              </summary>
              <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-3">
                <Switch
                  checked={scanSecrets}
                  onChange={(checked) => updateScanOption("scanSecrets", checked)}
                  label="Secrets"
                  disabled={running}
                />
                <Switch
                  checked={scanVulns}
                  onChange={(checked) =>
                    updateScanOption("scanVulnerabilities", checked)
                  }
                  label="Vulnerabilities"
                  disabled={running}
                />
                <Switch
                  checked={includeGit}
                  onChange={(checked) => updateScanOption("includeGit", checked)}
                  label="Include .git"
                  disabled={running}
                />
                <Switch
                  checked={followSymlinks}
                  onChange={(checked) =>
                    updateScanOption("followSymlinks", checked)
                  }
                  label="Follow symlinks"
                  disabled={running}
                />
                <label className="flex items-center gap-2 text-[12px] text-text-muted">
                  Max file size
                  <input
                    type="number"
                    value={maxSizeKb}
                    min={1}
                    max={10240}
                    onChange={(event) =>
                      updateScanOption(
                        "maxFileSizeKb",
                        Number(event.target.value) || 1024,
                      )
                    }
                    disabled={running}
                    className="w-20 rounded-sm border border-border bg-surface-secondary px-2 py-1 font-mono text-xs text-text-primary disabled:cursor-not-allowed disabled:opacity-50"
                  />
                  KB
                </label>
              </div>
            </details>
            {!scanOptions.resolved && (
              <InlineState
                tone="running"
                compact
                title="Loading scan defaults"
                description="Run scan becomes available after the local settings attempt finishes."
              />
            )}
            {settingsLoadError && settings === null && scanOptions.resolved && (
              <InlineState
                tone="unavailable"
                compact
                title="Using fallback scan defaults"
                description="Local settings could not be loaded. The displayed controls are the exact options that will be submitted."
              />
            )}
            {running && progress && (
              <InlineState
                tone="running"
                compact
                title="Scanning project"
                description={progress.file}
                progress={
                  <ProgressBar
                    indeterminate={!progress.total}
                    value={progress.done ?? 0}
                    max={progress.total ?? 0}
                    label={progressLabel}
                  />
                }
                action={
                  result ? (
                    <span className="text-[11px] text-text-muted">Previous results remain available below.</span>
                  ) : undefined
                }
              />
            )}
            {cancelled && result && !running && (
              <div className="mt-3">
                <ScanCancelled hasPreviousResults />
              </div>
            )}
            {scanUnavailable && !running && (
              <div className="mt-3">
                <InlineState
                  tone="unavailable"
                  compact
                  title="No scan categories selected"
                  description="Enable secrets or vulnerabilities to run a source scan."
                />
              </div>
            )}
            {error && result && !running && (
              <div className="mt-3">
                <ScanError detail={error} onRetry={run} />
              </div>
            )}
          </>
        }
      >
        <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Project folder
        </label>
        <FolderPicker
          value={path}
          onChange={changePath}
          disabled={running}
          inputLabel="Project folder path"
          buttonLabel="Browse…"
        />
      </TargetBar>

      {result && (
        <section aria-label="Scan summary" className="grid grid-cols-2 overflow-hidden rounded-sm border border-border bg-surface-secondary min-[700px]:grid-cols-5">
          <SummaryMetric label="Files" value={result.summary.filesScanned.toLocaleString()} />
          <SummaryMetric label="Secrets" value={result.summary.secretsFound.toLocaleString()} />
          <SummaryMetric label="Vulnerabilities" value={result.summary.vulnerabilitiesFound.toLocaleString()} />
          <SummaryMetric label="Critical / High" value={`${result.summary.critical} / ${result.summary.high}`} />
          <SummaryMetric label="Scanned" value={`${fmtBytes(result.summary.bytesScanned)} · ${fmtDuration(result.summary.durationMs)}`} />
        </section>
      )}

      {result && result.findings.length > 0 && (
        <section aria-label="Source scan results" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <ResultsToolbar
            countLabel={`${filtered.length} of ${result.findings.length} findings`}
            filters={
              <>
                <Select
                  aria-label="Finding category"
                  value={tab}
                  onChange={(event) => {
                    setTab(event.target.value as typeof tab);
                  }}
                  variant="compact"
                >
                  <option value="all">All categories</option>
                  <option value="secret">Secrets ({result.summary.secretsFound})</option>
                  <option value="vulnerability">Vulnerabilities ({result.summary.vulnerabilitiesFound})</option>
                </Select>
                <Select
                  aria-label="Finding severity"
                  value={sevFilter}
                  onChange={(event) => {
                    setSevFilter(event.target.value);
                  }}
                  variant="compact"
                >
                  {SEVERITIES.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity === "all" ? "All severities" : severity}
                    </option>
                  ))}
                </Select>
                <Select
                  aria-label="Finding language"
                  value={langFilter}
                  onChange={(event) => {
                    setLangFilter(event.target.value);
                  }}
                  variant="compact"
                >
                  {languages.map((language) => (
                    <option key={language} value={language}>
                      {language === "all" ? "All languages" : language}
                    </option>
                  ))}
                </Select>
              </>
            }
            search={
              <label className="relative min-w-0">
                <span className="sr-only">Search findings</span>
                <Search
                  size={13}
                  aria-hidden="true"
                  className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
                />
                <input
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value);
                  }}
                  placeholder="Search findings…"
                  className="w-44 rounded-sm border border-border bg-surface-secondary py-1.5 pl-8 pr-2 text-[12px] text-text-primary placeholder:text-text-muted"
                />
              </label>
            }
            actions={
              <Button
                type="button"
                onClick={copyJson}
                variant="outline"
                size="md"
              >
                <Clipboard size={13} aria-hidden="true" />
                Copy JSON
              </Button>
            }
          />

          {filtered.length > 0 ? (
            <SplitWorkspace
              listLabel="Findings"
              detailLabel="Finding detail"
              hasSelection={hasExplicitSelection}
              onBackToList={() => setSelectedFindingId(null)}
              list={
                <div className="max-h-[39rem] overflow-y-auto divide-y divide-border">
                  {filtered.map((finding) => {
                    const Icon = finding.category === "secret" ? KeyRound : FileCode2;
                    const current = selectedFinding?.id === finding.id;
                    return (
                      <button
                        key={finding.id}
                        type="button"
                        aria-current={current}
                        onClick={() => setSelectedFindingId(finding.id)}
                        className={`flex w-full items-start gap-3 border-l-2 px-3 py-3 text-left transition-colors ${ current ? "border-accent-glow bg-accent-subtle" : "border-transparent hover:bg-surface-hover" }`}
                      >
                        <Icon size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-text-muted" />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-1.5">
                            <span className="truncate text-[12px] font-medium text-text-primary">{finding.ruleName}</span>
                            <SeverityBadge severity={finding.severity} />
                          </span>
                          <span className="mt-1 block truncate font-mono text-[11px] text-text-muted">
                            {finding.filePath}:{finding.line}
                          </span>
                          <span className="mt-1 block truncate text-[11px] text-text-muted">{finding.matchText}</span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              }
              detail={
                selectedFinding ? (
                  <FindingDetail finding={selectedFinding} onCopy={copyFinding} onOpenFile={openFile} />
                ) : (
                  <InlineState tone="empty" title="Select a finding" compact />
                )
              }
            />
          ) : (
            <InlineState
              tone="empty"
              title="No findings match the current filters"
              description="Widen the category, severity, or language filters, or clear the search."
              action={
                <button
                  type="button"
                  onClick={() => {
                    setTab("all");
                    setSevFilter("all");
                    setLangFilter("all");
                    setSearch("");
                  }}
                  className="rounded-sm border border-border bg-surface-tertiary px-2.5 py-1.5 text-[12px] font-medium text-text-primary hover:bg-surface-active"
                >
                  Clear filters
                </button>
              }
            />
          )}
        </section>
      )}

      {result && result.findings.length === 0 && (
        <InlineState
          tone="empty"
          title="No findings detected"
          description="The scan completed without finding exposed secrets or vulnerable source patterns."
          action={
            <Button
              type="button"
              onClick={copyJson}
              variant="outline"
              size="md"
            >
              <Clipboard size={13} aria-hidden="true" />
              Copy JSON
            </Button>
          }
        />
      )}

      {!result && error && !running && <ScanError detail={error} onRetry={run} />}

      {!result && cancelled && !running && <ScanCancelled />}

      {!result && !error && !cancelled && !running && !scanUnavailable && (
        <InlineState
          tone="idle"
          title="Ready to scan"
          description="Choose a project folder, review optional advanced settings, and run the scan."
        />
      )}

      {!result && running && !progress && (
        <InlineState tone="running" title="Starting source scan" description="Preparing the selected project." />
      )}
    </ToolPage>
  );
}

function SummaryMetric({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="min-w-0 border-b border-r border-border px-3 py-2.5 last:border-r-0 min-[700px]:border-b-0">
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">{label}</p>
      <p className="mt-1 truncate text-[13px] font-medium tabular-nums text-text-primary" title={value}>
        {value}
      </p>
    </div>
  );
}

function ScanError({ detail, onRetry }: { detail: string; onRetry: () => void }): JSX.Element {
  return (
    <InlineState
      tone="error"
      compact
      title="The selected folder could not be scanned"
      description="Correct the folder path or scan settings, then try again."
      action={
        <>
          <Button
            type="button"
            onClick={onRetry}
            variant="danger"
            size="md"
          >
            Retry scan
          </Button>
          <details className="text-[11px] text-text-muted">
            <summary className="cursor-pointer hover:text-text-primary">Details</summary>
            <pre className="selectable mt-2 max-h-28 max-w-full overflow-auto whitespace-pre-wrap rounded-sm border border-border bg-surface-primary p-2 font-mono text-[11px] text-text-muted">
              {detail}
            </pre>
          </details>
        </>
      }
    />
  );
}

function ScanCancelled({ hasPreviousResults = false }: { hasPreviousResults?: boolean }): JSX.Element {
  return (
    <InlineState
      tone="idle"
      compact
      title="Scan cancelled"
      description={
        hasPreviousResults
          ? "The previous completed results are still available."
          : "No results were changed. You can run the scan again when ready."
      }
    />
  );
}
