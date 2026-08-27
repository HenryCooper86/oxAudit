import { useEffect, useRef, useState, type JSX } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Ban, Boxes, ExternalLink, Play, Search } from "lucide-react";
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
import { latestCompletedRun } from "../lib/durableRuns";
import { fmtDate } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { DependencyScanResult, LockfileInfo, Vulnerability } from "../lib/types";
import { Button, Switch } from "../components/ui";
import { RunTimeline } from "../features/runs/RunTimeline";

const vulnerabilityKey = (v: Vulnerability) => `${v.id}:${v.packageName}:${v.installedVersion}`;
type FailedOperation = "discovery" | "check";

export function DepsScanPage() {
  const addRecentScan = useAppStore((state) => state.addRecentScan);
  const setActiveProjectStore = useAppStore((state) => state.setActiveProject);
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const activeProject = useAppStore((state) => state.activeProject);
  const push = useToastStore((state) => state.push);

  const [path, setPath] = useState(activeProject ?? "");
  const [running, setRunning] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [preview, setPreview] = useState<LockfileInfo[] | null>(null);
  const [result, setResult] = useState<DependencyScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [failedOperation, setFailedOperation] = useState<FailedOperation | null>(null);
  const [phase, setPhase] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [progressBridgeAvailable, setProgressBridgeAvailable] = useState<boolean | null>(null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [offline, setOffline] = useState(false);

  const unlistenRef = useRef<UnlistenFn | null>(null);
  const discoveryRequestRef = useRef(0);
  const pathRequestRef = useRef(0);
  const historyRequestRef = useRef(0);

  useEffect(() => {
    const requestedPath = path.trim();
    const requestId = ++historyRequestRef.current;
    if (!requestedPath) return;

    void (async () => {
      try {
        const runs = await api.listCanonicalRuns("dependencies");
        const saved = latestCompletedRun(runs, "dependencies", requestedPath);
        if (!saved || requestId !== historyRequestRef.current) return;
        const restored = await api.loadCanonicalProjection<DependencyScanResult>(saved.id);
        if (requestId !== historyRequestRef.current) return;
        setResult(restored);
        setPreview(
          restored.summary.lockfilesFound.map((lockfilePath) => ({
            path: lockfilePath,
            kind: lockfilePath.split(/[\\/]/).pop() ?? "?",
            packages: 0,
          })),
        );
        setPageStatus("deps-scan", {
          label: `Saved dependency results · ${restored.summary.vulnerabilitiesFound} vulnerabilities`,
          tone: "success",
        });
      } catch {
        // History is a convenience surface. A missing/corrupt saved projection
        // must never prevent a fresh scan from running.
      }
    })();
  }, [path, setPageStatus]);
  useEffect(() => {
    let disposed = false;
    const register = async () => {
      try {
        const unlisten = await listen<{ phase: string; done?: number; total?: number }>("deps://progress", (event) => {
          if (!disposed) {
            setPhase(event.payload.phase);
            setProgress({ done: event.payload.done ?? 0, total: event.payload.total ?? 0 });
          }
        });
        if (disposed) {
          unlisten();
        } else {
          setProgressBridgeAvailable(true);
          unlistenRef.current = unlisten;
        }
      } catch {
        if (!disposed) setProgressBridgeAvailable(false);
      }
    };

    void register();
    return () => {
      disposed = true;
      unlistenRef.current?.();
      unlistenRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!running) return;
    setPageStatus("deps-scan", {
      label: "Checking dependencies",
      tone: "running",
      detail: phase === "parsing" ? "Parsing lockfiles" : phase === "querying-osv" ? "Querying OSV" : undefined,
    });
  }, [phase, running, setPageStatus]);

  const changePath = (nextPath: string) => {
    if (nextPath === path) return;
    const activationId = ++pathRequestRef.current;
    discoveryRequestRef.current += 1;
    historyRequestRef.current += 1;
    setPath(nextPath);
    setDiscovering(false);
    setPreview(null);
    setResult(null);
    setError(null);
    setFailedOperation(null);
    setProgress(null);
    setPhase(null);
    setSelectedKey(null);
    setQuery("");
    clearPageStatus("deps-scan");
    void resolveRuntimeProject(nextPath || null, api.setActiveProject).then((outcome) => {
      setActiveProjectStore(outcome.runtimePath);
      if (
        activationId === pathRequestRef.current &&
        outcome.unavailablePath === nextPath &&
        outcome.warning
      ) {
        push("error", outcome.warning);
      }
    });
  };

  const findLockfiles = async () => {
    if (!path || running || discovering) return;
    const requestId = ++discoveryRequestRef.current;
    historyRequestRef.current += 1;
    const requestedPath = path;
    setDiscovering(true);
    setError(null);
    setFailedOperation(null);
    setPageStatus("deps-scan", { label: "Finding lockfiles", tone: "running" });
    try {
      const runtime = await resolveRuntimeProject(
        requestedPath,
        api.setActiveProject,
      );
      setActiveProjectStore(runtime.runtimePath);
      if (
        requestId !== discoveryRequestRef.current ||
        runtime.runtimePath !== requestedPath
      ) {
        return;
      }
      const foundLockfiles = await api.findLockfiles(requestedPath);
      if (requestId !== discoveryRequestRef.current) return;
      setPreview(foundLockfiles);
      if (result) {
        setPageStatus("deps-scan", {
          label: `Dependencies checked · ${result.summary.vulnerabilitiesFound} vulnerabilities`,
          tone: "success",
        });
      } else {
        clearPageStatus("deps-scan");
      }
    } catch (findError) {
      if (requestId !== discoveryRequestRef.current) return;
      setError(String(findError));
      setFailedOperation("discovery");
      setPageStatus("deps-scan", { label: "Lockfile discovery failed", tone: "error" });
    } finally {
      if (requestId === discoveryRequestRef.current) setDiscovering(false);
    }
  };

  const run = async () => {
    if (!path || running || discovering) return;
    setRunning(true);
    setError(null);
    setFailedOperation(null);
    setProgress({ done: 0, total: 0 });
    const requestId = ++discoveryRequestRef.current;
    const requestedPath = path;
    try {
      const runtime = await resolveRuntimeProject(
        requestedPath,
        api.setActiveProject,
      );
      setActiveProjectStore(runtime.runtimePath);
      if (
        requestId !== discoveryRequestRef.current ||
        runtime.runtimePath !== requestedPath
      ) {
        return;
      }
      const scanResult = await api.scanDependencies(requestedPath, offline);
      setResult(scanResult);
      setSelectedKey(null);
      setPreview(
        scanResult.summary.lockfilesFound.map((lockfilePath) => {
          const kind = lockfilePath.split(/[\\/]/).pop() ?? "?";
          return { path: lockfilePath, kind, packages: 0 };
        }),
      );
      setPageStatus("deps-scan", {
        label: `Dependencies checked · ${scanResult.summary.vulnerabilitiesFound} vulnerabilities`,
        tone: "success",
      });
      addRecentScan({
        id: `deps-${Date.now()}`,
        kind: "deps",
        path,
        at: new Date().toISOString(),
        findings: scanResult.summary.vulnerabilitiesFound,
        critical: scanResult.vulnerabilities.filter((vulnerability) => vulnerability.severity === "critical").length,
        high: scanResult.vulnerabilities.filter((vulnerability) => vulnerability.severity === "high").length,
      });
      push(
        "success",
        `Dependency scan complete — ${scanResult.summary.vulnerabilitiesFound} vulnerabilities across ${scanResult.summary.packagesQueried} packages`,
      );
    } catch (scanError) {
      setError(String(scanError));
      setFailedOperation("check");
      setPageStatus("deps-scan", { label: "Dependency check failed", tone: "error" });
      push("error", "Dependency checking failed");
    } finally {
      setRunning(false);
      setProgress(null);
      setPhase(null);
    }
  };

  const cancel = async () => {
    try {
      await api.cancelDependencyScan();
    } catch {
      // The running command remains the authoritative terminal result.
    }
  };

  const openReference = async (reference: string) => {
    try {
      await openUrl(reference);
    } catch {
      push("error", "The advisory reference could not be opened");
    }
  };

  const vulns = result?.vulnerabilities ?? [];
  const filteredVulns = vulns.filter((vulnerability) => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return true;
    return `${vulnerability.id} ${vulnerability.packageName} ${vulnerability.summary} ${vulnerability.aliases.join(" ")}`
      .toLowerCase()
      .includes(normalizedQuery);
  });
  const selected = filteredVulns.find((v) => vulnerabilityKey(v) === selectedKey) ?? filteredVulns[0] ?? null;
  const hasExplicitSelection = selectedKey !== null && selected !== null && vulnerabilityKey(selected) === selectedKey;
  const critical = vulns.filter((vulnerability) => vulnerability.severity === "critical").length;
  const high = vulns.filter((vulnerability) => vulnerability.severity === "high").length;
  const progressLabel =
    phase === "parsing"
      ? "Parsing lockfiles…"
      : phase === "querying-osv"
        ? "Querying OSV vulnerability database…"
        : "Checking dependencies…";

  return (
    <ToolPage
      title="Dependency Scan"
      description="Detect supported lockfiles and check their pinned packages against the OSV vulnerability database."
    >
      <TargetBar
        primary={
          <>
            <Button
              type="button"
              onClick={findLockfiles}
              disabled={!path || running || discovering}
              variant="outline"
              size="md"
            >
              <Search size={13} aria-hidden="true" />
              {discovering ? "Finding…" : "Find lockfiles"}
            </Button>
            {running ? (
              <Button type="button" onClick={() => void cancel()} variant="danger" size="md">
                <Ban size={13} aria-hidden="true" />Cancel
              </Button>
            ) : (
              <Button type="button" onClick={run} disabled={!path || discovering} variant="primary" size="md">
                <Play size={13} aria-hidden="true" />Check dependencies
              </Button>
            )}
            <Switch checked={offline} onChange={setOffline} disabled={running || discovering} label="Offline (use exact saved OSV queries only)" />
          </>
        }
        secondary={
          <>
            {running && (
              <InlineState
                tone="running"
                compact
                title="Checking dependencies"
                description={
                  result
                    ? "Previous completed results remain available below."
                    : progressBridgeAvailable === false
                      ? "Live progress is unavailable; the dependency check is still running."
                      : undefined
                }
                progress={
                  progressBridgeAvailable === false ? undefined : (
                    <ProgressBar
                      indeterminate={!progress?.total}
                      value={progress?.done ?? 0}
                      max={progress?.total ?? 0}
                      label={progressLabel}
                    />
                  )
                }
              />
            )}
            {discovering && (
              <InlineState
                tone="running"
                compact
                title="Finding lockfiles"
                description="Looking for supported lockfiles in the selected project."
              />
            )}
            {progressBridgeAvailable === false && (
              <InlineState
                tone="unavailable"
                compact
                title="Live progress unavailable"
                description="Dependency checks can still run, but live progress updates are unavailable in this environment."
              />
            )}
            {preview && preview.length > 0 && !running && (
              <div className="flex flex-wrap gap-2" aria-label="Detected lockfiles">
                {preview.map((lockfile) => (
                  <span
                    key={lockfile.path}
                    className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-secondary px-2.5 py-1 font-mono text-[11px] text-text-muted"
                  >
                    <Boxes size={11} aria-hidden="true" className="text-info" />
                    {lockfile.path.split(/[\\/]/).pop()}
                    <span className="text-text-muted">({lockfile.packages} pkgs)</span>
                  </span>
                ))}
              </div>
            )}
            {error && result && !running && failedOperation && (
              <DependencyError
                detail={error}
                operation={failedOperation}
                onRetry={failedOperation === "discovery" ? findLockfiles : run}
              />
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
          disabled={running || discovering}
          inputLabel="Project folder path"
          buttonLabel="Browse…"
        />
      </TargetBar>

      <RunTimeline
        active={!running && result ? "completed" : phase === "parsing" ? "detecting" : phase === "querying-osv" || phase === "exploitation-signal" ? "enriching" : "discovering"}
        running={running || discovering}
        hasCompletedResult={Boolean(result)}
      />

      {result && (
        <section
          aria-label="Dependency scan summary"
          className="grid grid-cols-2 overflow-hidden rounded-sm border border-border bg-surface-secondary min-[700px]:grid-cols-5"
        >
          <SummaryMetric label="Lockfiles" value={result.summary.lockfilesFound.length.toLocaleString()} />
          <SummaryMetric label="Packages found" value={result.summary.packagesFound.toLocaleString()} />
          <SummaryMetric label="Packages checked" value={result.summary.packagesQueried.toLocaleString()} />
          <SummaryMetric label="Vulnerabilities" value={vulns.length.toLocaleString()} />
          <SummaryMetric label="Critical / High" value={`${critical} / ${high}`} />
        </section>
      )}

      {result && vulns.length > 0 && (
        <section aria-label="Dependency vulnerabilities" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <ResultsToolbar
            countLabel={`${filteredVulns.length} of ${vulns.length} vulnerabilities`}
            search={
              <label className="relative min-w-0">
                <span className="sr-only">Search dependency vulnerabilities</span>
                <Search
                  size={13}
                  aria-hidden="true"
                  className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
                />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search package or advisory…"
                  className="w-52 rounded-sm border border-border bg-surface-secondary py-1.5 pl-8 pr-2 text-[12px] text-text-primary placeholder:text-text-muted"
                />
              </label>
            }
          />
          {filteredVulns.length > 0 ? (
            <SplitWorkspace
              panelId="dependency-vulnerabilities"
              listLabel="Vulnerable packages"
              detailLabel="Advisory detail"
              hasSelection={hasExplicitSelection}
              onBackToList={() => setSelectedKey(null)}
              list={<VulnerabilityTable vulnerabilities={filteredVulns} selected={selected} onSelect={setSelectedKey} />}
              detail={selected ? <AdvisoryDetail vulnerability={selected} onOpenReference={openReference} /> : <InlineState tone="empty" compact title="Select an advisory" />}
            />
          ) : (
            <InlineState
              tone="empty"
              compact
              title="No vulnerabilities match the current search"
              description="Clear or broaden the search to review the remaining advisories."
              action={
                <button
                  type="button"
                  onClick={() => setQuery("")}
                  className="rounded-sm border border-border bg-surface-tertiary px-2.5 py-1.5 text-[12px] font-medium text-text-primary hover:bg-surface-active"
                >
                  Clear search
                </button>
              }
            />
          )}
        </section>
      )}

      {result && vulns.length === 0 && (
        <InlineState tone="empty" title="OSV returned no published vulnerabilities for the queried packages." />
      )}

      {!result && error && !running && failedOperation && (
        <DependencyError
          detail={error}
          operation={failedOperation}
          onRetry={failedOperation === "discovery" ? findLockfiles : run}
        />
      )}

      {!result && !error && !running && preview?.length === 0 && (
        <InlineState tone="empty" title="No supported lockfiles were found in this project." />
      )}

      {!result && !error && !running && preview === null && (
        <InlineState tone="idle" title="Choose a project to detect supported lockfiles." />
      )}
    </ToolPage>
  );
}

function VulnerabilityTable({
  vulnerabilities,
  selected,
  onSelect,
}: {
  vulnerabilities: Vulnerability[];
  selected: Vulnerability | null;
  onSelect: (key: string) => void;
}): JSX.Element {
  return (
    <div className="max-h-[39rem] min-w-0 overflow-auto" aria-label="Scrollable vulnerable package table">
      <table className="min-w-[44rem] w-full table-fixed border-collapse text-left">
        <caption className="sr-only">Vulnerable packages and their advisory risk</caption>
        <thead className="border-b border-border bg-surface-secondary text-[12px] font-semibold uppercase tracking-[0.1em] text-text-muted">
          <tr>
            <th scope="col" className="w-[31%] px-3 py-2">Package</th>
            <th scope="col" className="w-[17%] px-3 py-2">Installed</th>
            <th scope="col" className="w-[18%] px-3 py-2">Fixed</th>
            <th scope="col" className="w-[18%] px-3 py-2">Ecosystem</th>
            <th scope="col" className="w-[16%] px-3 py-2">Risk</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {vulnerabilities.map((vulnerability) => {
            const current = selected !== null && vulnerabilityKey(selected) === vulnerabilityKey(vulnerability);
            const select = () => onSelect(vulnerabilityKey(vulnerability));
            return (
              <tr
                key={vulnerabilityKey(vulnerability)}
                tabIndex={0}
                aria-current={current}
                aria-label={`Select ${vulnerability.packageName} advisory ${vulnerability.id}`}
                onClick={select}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    select();
                  }
                }}
                className={`cursor-pointer border-l-2 text-[13px] text-text-secondary transition-colors ${ current ? "border-accent-glow bg-accent-subtle" : "border-transparent hover:bg-surface-hover" }`}
              >
                <td className="min-w-0 px-3 py-2.5">
                  <span className="block truncate font-mono text-[14px] font-medium text-text-primary">{vulnerability.packageName}</span>
                  <span className="mt-0.5 flex items-center gap-1.5 truncate text-[11px] text-text-muted">
                    {vulnerability.id}
                    {vulnerability.knownExploited && (
                      <span
                        title={
                          vulnerability.ransomware
                            ? "In CISA KEV — used in ransomware campaigns"
                            : "In CISA's Known Exploited Vulnerabilities catalog"
                        }
                        className="inline-flex shrink-0 items-center rounded-full bg-sev-critical px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-wide text-white"
                      >
                        {vulnerability.ransomware ? "KEV · ransomware" : "KEV"}
                      </span>
                    )}
                    {vulnerability.publicExploit && (
                      <span
                        title="Public exploit code exists for this CVE (Exploit-DB)"
                        className="inline-flex shrink-0 items-center rounded-full bg-sev-high px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-wide text-white"
                      >
                        PoC
                      </span>
                    )}
                    {vulnerability.directUsage?.referenced === true && (
                      <span
                        title={`Directly referenced by this project's source (${vulnerability.directUsage.referencedFiles} file${vulnerability.directUsage.referencedFiles === 1 ? "" : "s"}, e.g. ${vulnerability.directUsage.exampleFile ?? "…"})`}
                        className="inline-flex shrink-0 items-center rounded-full border border-accent px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-wide text-accent"
                      >
                        in use
                      </span>
                    )}
                    {vulnerability.epss !== null && (
                      <span
                        title={`EPSS: ${(vulnerability.epss * 100).toFixed(1)}% chance of exploitation in 30 days`}
                        className="shrink-0 font-mono text-[10px] tabular-nums text-text-muted"
                      >
                        EPSS {(vulnerability.epss * 100).toFixed(0)}%
                      </span>
                    )}
                  </span>
                </td>
                <td className="truncate px-3 py-2.5 font-mono text-text-secondary" title={vulnerability.installedVersion}>
                  {vulnerability.installedVersion}
                </td>
                <td className="truncate px-3 py-2.5 font-mono text-text-secondary" title={vulnerability.fixedVersions.join(", ")}>
                  {vulnerability.fixedVersions[0] ?? "—"}
                </td>
                <td className="truncate px-3 py-2.5 text-text-secondary" title={vulnerability.ecosystem}>
                  {vulnerability.ecosystem}
                </td>
                <td className="px-3 py-2.5"><SeverityBadge severity={vulnerability.severity} /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function AdvisoryDetail({
  vulnerability,
  onOpenReference,
}: {
  vulnerability: Vulnerability;
  onOpenReference: (reference: string) => Promise<void>;
}): JSX.Element {
  return (
    <article className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-[12px] text-info">{vulnerability.id}</p>
          <h2 className="mt-1 break-words text-[16px] font-semibold text-text-primary">{vulnerability.packageName}</h2>
          <p className="mt-1 text-[13px] text-text-muted">{vulnerability.summary || "No advisory summary provided."}</p>
        </div>
        <SeverityBadge severity={vulnerability.severity} />
      </div>

      <section className="mt-5 space-y-4 text-[13px]">
        <DetailSection label="Details">
          <p className="whitespace-pre-wrap leading-relaxed text-text-secondary">{vulnerability.details || vulnerability.summary || "No additional details provided."}</p>
        </DetailSection>
        {(vulnerability.knownExploited || vulnerability.publicExploit || vulnerability.epss !== null) && (
          <DetailSection label="Exploitation">
            <div className="flex flex-wrap items-center gap-2">
              {vulnerability.knownExploited && (
                <span className="inline-flex items-center rounded-full bg-sev-critical px-2 py-0.5 font-mono text-[11px] font-semibold text-white">
                  {vulnerability.ransomware ? "CISA KEV · ransomware campaign" : "CISA KEV — exploited in the wild"}
                </span>
              )}
              {vulnerability.publicExploit && (
                <span className="inline-flex items-center rounded-full bg-sev-high px-2 py-0.5 font-mono text-[11px] font-semibold text-white">
                  Public exploit available
                </span>
              )}
              {vulnerability.epss !== null && (
                <span className="text-text-secondary">
                  EPSS <span className="font-mono text-text-primary">{(vulnerability.epss * 100).toFixed(1)}%</span>
                  {vulnerability.epssPercentile !== null && (
                    <span className="text-text-muted"> ({(vulnerability.epssPercentile * 100).toFixed(0)}th percentile)</span>
                  )}
                  <span className="text-text-muted"> chance of exploitation in 30 days</span>
                </span>
              )}
            </div>
          </DetailSection>
        )}
        {vulnerability.directUsage && (
          <DetailSection label="Reachability">
            <p className="leading-relaxed text-text-secondary">
              {vulnerability.directUsage.referenced === true && (
                <>
                  Directly referenced by this project's source —{" "}
                  <span className="font-mono text-text-primary">{vulnerability.directUsage.referencedFiles}</span>{" "}
                  file{vulnerability.directUsage.referencedFiles === 1 ? "" : "s"}, e.g.{" "}
                  <span className="font-mono text-text-primary">{vulnerability.directUsage.exampleFile ?? "…"}</span>.
                </>
              )}
              {vulnerability.directUsage.referenced === false && (
                <>
                  No direct reference found in this project's source. The package may still be reachable
                  through other dependencies — this answers where it is imported from, not whether it can
                  be reached at all.
                </>
              )}
              {vulnerability.directUsage.referenced === null && (
                <>
                  Direct-usage reachability is not mapped for this ecosystem, so oxAudit says nothing
                  either way.
                </>
              )}
            </p>
          </DetailSection>
        )}
        <div className="grid gap-4 min-[540px]:grid-cols-2">
          <DetailSection label="Installed version">
            <p className="font-mono text-text-primary">{vulnerability.installedVersion}</p>
          </DetailSection>
          <DetailSection label="Ecosystem">
            <p className="text-text-primary">{vulnerability.ecosystem}</p>
          </DetailSection>
          <DetailSection label="CVSS">
            <p className="font-mono text-text-primary">{vulnerability.cvssScore === null ? "Not published" : vulnerability.cvssScore.toFixed(1)}</p>
          </DetailSection>
          <DetailSection label="Published">
            <p className="text-text-primary">{vulnerability.published ? fmtDate(vulnerability.published) : "Not published"}</p>
          </DetailSection>
          <DetailSection label="Affected range">
            <p className="font-mono text-text-primary">{vulnerability.affectedRange ?? "Not published"}</p>
          </DetailSection>
          <DetailSection label="Lockfile">
            <p className="break-all font-mono text-text-primary">{vulnerability.lockfile || "Not reported"}</p>
          </DetailSection>
        </div>
        <DetailSection label="Advisory aliases">
          {vulnerability.aliases.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {vulnerability.aliases.map((alias) => (
                <span key={alias} className="rounded-sm border border-border bg-surface-tertiary px-1.5 py-0.5 font-mono text-[11px] text-info">
                  {alias}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-text-muted">No aliases reported.</p>
          )}
        </DetailSection>
        <DetailSection label="Fixed versions">
          {vulnerability.fixedVersions.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {vulnerability.fixedVersions.map((version) => (
                <span key={version} className="rounded-sm border border-success-border bg-success-subtle px-1.5 py-0.5 font-mono text-[11px] text-success">
                  {version}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-warning">No fixed version published yet.</p>
          )}
        </DetailSection>
        {vulnerability.references.length > 0 && (
          <DetailSection label="References">
            <div className="flex flex-wrap gap-1.5">
              {vulnerability.references.map((reference) => (
                <button
                  key={reference}
                  type="button"
                  onClick={() => {
                    void onOpenReference(reference);
                  }}
                  className="inline-flex max-w-full items-center gap-1 rounded-sm border border-border bg-surface-tertiary px-2 py-1 text-[12px] text-info hover:border-info"
                >
                  <ExternalLink size={10} aria-hidden="true" />
                  <span className="max-w-64 truncate">{reference.replace(/^https?:\/\//, "")}</span>
                </button>
              ))}
            </div>
          </DetailSection>
        )}
      </section>
    </article>
  );
}

function DetailSection({ label, children }: { label: string; children: JSX.Element }): JSX.Element {
  return (
    <div>
      <h3 className="mb-1 text-[12px] font-semibold uppercase tracking-[0.1em] text-text-muted">{label}</h3>
      {children}
    </div>
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

function DependencyError({
  detail,
  operation,
  onRetry,
}: {
  detail: string;
  operation: FailedOperation;
  onRetry: () => void;
}): JSX.Element {
  const discovery = operation === "discovery";
  return (
    <InlineState
      tone="error"
      compact
      title={discovery ? "Lockfile discovery failed" : "Dependency checking failed"}
      action={
        <>
          <Button
            type="button"
            onClick={onRetry}
            variant="danger"
            size="md"
          >
            {discovery ? "Retry discovery" : "Retry dependency check"}
          </Button>
          <details className="text-[11px] text-text-muted">
            <summary className="cursor-pointer hover:text-text-primary">Technical details</summary>
            <pre className="selectable mt-2 max-h-28 max-w-full overflow-auto whitespace-pre-wrap rounded-sm border border-border bg-surface-primary p-2 font-mono text-[11px] text-text-muted">
              {detail}
            </pre>
          </details>
        </>
      }
    />
  );
}
