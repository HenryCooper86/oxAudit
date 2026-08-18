import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openPath } from "@tauri-apps/plugin-opener";
import { Ban, Clipboard, FileCode2, KeyRound, Play, Search } from "lucide-react";
import { FindingDetail } from "../components/FindingDetail";
import { FolderPicker } from "../components/FolderPicker";
import { ProgressBar } from "../components/ProgressBar";
import { SeverityBadge } from "../components/SeverityBadge";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { Switch } from "../components/workbench/Switch";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { fmtBytes, fmtDuration } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { Finding, ScanProgress, ScanResult, Severity } from "../lib/types";

const SEVERITIES: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];

export function SourceScanPage() {
  const addRecentScan = useAppStore((state) => state.addRecentScan);
  const setActiveProjectStore = useAppStore((state) => state.setActiveProject);
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const push = useToastStore((state) => state.push);

  const [path, setPath] = useState("");
  const [scanSecrets, setScanSecrets] = useState(true);
  const [scanVulns, setScanVulns] = useState(true);
  const [includeGit, setIncludeGit] = useState(false);
  const [followSymlinks, setFollowSymlinks] = useState(false);
  const [maxSizeKb, setMaxSizeKb] = useState(1024);

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

  const unlistenRef = useRef<UnlistenFn[]>([]);
  const cancellingRef = useRef(false);

  useEffect(() => {
    let disposed = false;
    const register = async () => {
      try {
        const [progressUnlisten, doneUnlisten] = await Promise.all([
          listen<ScanProgress>("scan://progress", (event) => {
            if (!disposed) setProgress(event.payload);
          }),
          listen<ScanProgress>("scan://done", (event) => {
            if (!disposed) setProgress((current) => ({ ...current, ...event.payload }));
          }),
        ]);
        if (disposed) {
          progressUnlisten();
          doneUnlisten();
        } else {
          unlistenRef.current = [progressUnlisten, doneUnlisten];
        }
      } catch {
        // The event bridge is unavailable when the UI is exercised in a browser.
      }
    };

    void register();
    return () => {
      disposed = true;
      for (const unlisten of unlistenRef.current) unlisten();
      unlistenRef.current = [];
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
    setPath(nextPath);
    resetResultState();
    void api.setActiveProject(nextPath).catch(() => undefined);
    setActiveProjectStore(nextPath || null);
  };

  const run = async () => {
    if (!path || running || (!scanSecrets && !scanVulns)) return;
    setRunning(true);
    cancellingRef.current = false;
    setCancelling(false);
    setError(null);
    setCancelled(false);
    setProgress({ phase: "walking" });
    try {
      const res = await api.scanProject({
        path,
        includeGit,
        followSymlinks,
        maxFileSizeKb: maxSizeKb,
        scanSecrets,
        scanVulnerabilities: scanVulns,
        extraIgnoredDirs: [],
      });
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

  const openFindingFile = (finding: Finding) => openPath(finding.filePath);

  const openFile = (finding: Finding) => {
    void openFindingFile(finding).catch(() => {
      push("error", "The finding file could not be opened");
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
              <button
                type="button"
                onClick={cancel}
                disabled={cancelling}
                className="inline-flex items-center gap-1.5 rounded-md border border-red-900/80 bg-red-950/30 px-3 py-2 text-[12px] font-medium text-red-300 hover:bg-red-950/60 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Ban size={13} aria-hidden="true" />
                {cancelling ? "Cancelling…" : "Cancel"}
              </button>
            )}
            <button
              type="button"
              onClick={run}
              disabled={!path || running || scanUnavailable}
              className="inline-flex items-center gap-1.5 rounded-md bg-accent-500 px-3.5 py-2 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Play size={13} aria-hidden="true" />
              {running ? "Scanning…" : "Run scan"}
            </button>
          </>
        }
        secondary={
          <>
            <details>
              <summary className="w-fit cursor-pointer text-[12px] font-medium text-stone-300 hover:text-stone-100">
                Advanced scan settings
              </summary>
              <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-3">
                <Switch checked={scanSecrets} onChange={setScanSecrets} label="Secrets" disabled={running} />
                <Switch
                  checked={scanVulns}
                  onChange={setScanVulns}
                  label="Vulnerabilities"
                  disabled={running}
                />
                <Switch checked={includeGit} onChange={setIncludeGit} label="Include .git" disabled={running} />
                <Switch
                  checked={followSymlinks}
                  onChange={setFollowSymlinks}
                  label="Follow symlinks"
                  disabled={running}
                />
                <label className="flex items-center gap-2 text-[12px] text-stone-400">
                  Max file size
                  <input
                    type="number"
                    value={maxSizeKb}
                    min={1}
                    max={10240}
                    onChange={(event) => setMaxSizeKb(Number(event.target.value) || 1024)}
                    disabled={running}
                    className="w-20 rounded-md border border-ink-600 bg-ink-900 px-2 py-1 font-mono text-xs text-stone-200 disabled:cursor-not-allowed disabled:opacity-50"
                  />
                  KB
                </label>
              </div>
            </details>
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
                    <span className="text-[11px] text-stone-400">Previous results remain available below.</span>
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
        <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.12em] text-stone-400">
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
        <section aria-label="Scan summary" className="grid grid-cols-2 overflow-hidden rounded-lg border border-ink-700 bg-ink-850 min-[700px]:grid-cols-5">
          <SummaryMetric label="Files" value={result.summary.filesScanned.toLocaleString()} />
          <SummaryMetric label="Secrets" value={result.summary.secretsFound.toLocaleString()} />
          <SummaryMetric label="Vulnerabilities" value={result.summary.vulnerabilitiesFound.toLocaleString()} />
          <SummaryMetric label="Critical / High" value={`${result.summary.critical} / ${result.summary.high}`} />
          <SummaryMetric label="Scanned" value={`${fmtBytes(result.summary.bytesScanned)} · ${fmtDuration(result.summary.durationMs)}`} />
        </section>
      )}

      {result && result.findings.length > 0 && (
        <section aria-label="Source scan results" className="overflow-hidden rounded-lg border border-ink-700 bg-ink-850">
          <ResultsToolbar
            countLabel={`${filtered.length} of ${result.findings.length} findings`}
            filters={
              <>
                <select
                  aria-label="Finding category"
                  value={tab}
                  onChange={(event) => {
                    setTab(event.target.value as typeof tab);
                  }}
                  className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-[12px] text-stone-300"
                >
                  <option value="all">All categories</option>
                  <option value="secret">Secrets ({result.summary.secretsFound})</option>
                  <option value="vulnerability">Vulnerabilities ({result.summary.vulnerabilitiesFound})</option>
                </select>
                <select
                  aria-label="Finding severity"
                  value={sevFilter}
                  onChange={(event) => {
                    setSevFilter(event.target.value);
                  }}
                  className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-[12px] text-stone-300"
                >
                  {SEVERITIES.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity === "all" ? "All severities" : severity}
                    </option>
                  ))}
                </select>
                <select
                  aria-label="Finding language"
                  value={langFilter}
                  onChange={(event) => {
                    setLangFilter(event.target.value);
                  }}
                  className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-[12px] text-stone-300"
                >
                  {languages.map((language) => (
                    <option key={language} value={language}>
                      {language === "all" ? "All languages" : language}
                    </option>
                  ))}
                </select>
              </>
            }
            search={
              <label className="relative min-w-0">
                <span className="sr-only">Search findings</span>
                <Search
                  size={13}
                  aria-hidden="true"
                  className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-stone-500"
                />
                <input
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value);
                  }}
                  placeholder="Search findings…"
                  className="w-44 rounded-md border border-ink-600 bg-ink-900 py-1.5 pl-8 pr-2 text-[12px] text-stone-200 placeholder:text-stone-600"
                />
              </label>
            }
            actions={
              <button
                type="button"
                onClick={copyJson}
                className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:border-ink-500 hover:bg-ink-700"
              >
                <Clipboard size={13} aria-hidden="true" />
                Copy JSON
              </button>
            }
          />

          {filtered.length > 0 ? (
            <SplitWorkspace
              listLabel="Findings"
              detailLabel="Finding detail"
              hasSelection={hasExplicitSelection}
              onBackToList={() => setSelectedFindingId(null)}
              list={
                <div className="max-h-[39rem] overflow-y-auto divide-y divide-ink-800">
                  {filtered.map((finding) => {
                    const Icon = finding.category === "secret" ? KeyRound : FileCode2;
                    const current = selectedFinding?.id === finding.id;
                    return (
                      <button
                        key={finding.id}
                        type="button"
                        aria-current={current}
                        onClick={() => setSelectedFindingId(finding.id)}
                        className={`flex w-full items-start gap-3 border-l-2 px-3 py-3 text-left transition-colors ${
                          current
                            ? "border-accent-500 bg-accent-500/5"
                            : "border-transparent hover:bg-ink-800"
                        }`}
                      >
                        <Icon size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-stone-500" />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-1.5">
                            <span className="truncate text-[12px] font-medium text-stone-200">{finding.ruleName}</span>
                            <SeverityBadge severity={finding.severity} />
                          </span>
                          <span className="mt-1 block truncate font-mono text-[11px] text-stone-400">
                            {finding.filePath}:{finding.line}
                          </span>
                          <span className="mt-1 block truncate text-[11px] text-stone-400">{finding.matchText}</span>
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
                  className="rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:bg-ink-700"
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
            <button
              type="button"
              onClick={copyJson}
              className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:bg-ink-700"
            >
              <Clipboard size={13} aria-hidden="true" />
              Copy JSON
            </button>
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
    <div className="min-w-0 border-b border-r border-ink-800 px-3 py-2.5 last:border-r-0 min-[700px]:border-b-0">
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-stone-400">{label}</p>
      <p className="mt-1 truncate text-[13px] font-medium tabular-nums text-stone-200" title={value}>
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
          <button
            type="button"
            onClick={onRetry}
            className="rounded-md border border-red-900/80 bg-red-950/40 px-2.5 py-1.5 text-[12px] font-medium text-red-200 hover:bg-red-950/70"
          >
            Retry scan
          </button>
          <details className="text-[11px] text-stone-400">
            <summary className="cursor-pointer hover:text-stone-200">Details</summary>
            <pre className="selectable mt-2 max-h-28 max-w-full overflow-auto whitespace-pre-wrap rounded border border-ink-700 bg-ink-950 p-2 font-mono text-[11px] text-stone-400">
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
