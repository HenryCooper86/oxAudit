import { useEffect, useRef, useState, type JSX } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Boxes, ExternalLink, Play, Search } from "lucide-react";
import { FolderPicker } from "../components/FolderPicker";
import { ProgressBar } from "../components/ProgressBar";
import { SeverityBadge } from "../components/SeverityBadge";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { fmtDate } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { DependencyScanResult, LockfileInfo, Vulnerability } from "../lib/types";

const vulnerabilityKey = (v: Vulnerability) => `${v.id}:${v.packageName}:${v.installedVersion}`;

export function DepsScanPage() {
  const addRecentScan = useAppStore((state) => state.addRecentScan);
  const setActiveProjectStore = useAppStore((state) => state.setActiveProject);
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const push = useToastStore((state) => state.push);

  const [path, setPath] = useState("");
  const [running, setRunning] = useState(false);
  const [preview, setPreview] = useState<LockfileInfo[] | null>(null);
  const [result, setResult] = useState<DependencyScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const unlistenRef = useRef<UnlistenFn | null>(null);
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
        if (disposed) unlisten();
        else unlistenRef.current = unlisten;
      } catch {
        // The event bridge is unavailable when the UI is exercised in a browser.
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
    setPath(nextPath);
    setPreview(null);
    setResult(null);
    setError(null);
    setProgress(null);
    setPhase(null);
    setSelectedKey(null);
    setQuery("");
    clearPageStatus("deps-scan");
    void api.setActiveProject(nextPath).catch(() => undefined);
    setActiveProjectStore(nextPath || null);
  };

  const findLockfiles = async () => {
    if (!path || running) return;
    setError(null);
    try {
      setPreview(await api.findLockfiles(path));
    } catch (findError) {
      setError(String(findError));
      setPageStatus("deps-scan", { label: "Dependency check failed", tone: "error" });
    }
  };

  const run = async () => {
    if (!path || running) return;
    setRunning(true);
    setError(null);
    setProgress({ done: 0, total: 0 });
    try {
      const scanResult = await api.scanDependencies(path);
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
      setPageStatus("deps-scan", { label: "Dependency check failed", tone: "error" });
      push("error", "Dependency checking failed");
    } finally {
      setRunning(false);
      setProgress(null);
      setPhase(null);
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
            <button
              type="button"
              onClick={findLockfiles}
              disabled={!path || running}
              className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-3 py-2 text-[12px] font-medium text-stone-200 hover:border-ink-500 hover:bg-ink-700 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Search size={13} aria-hidden="true" />
              Find lockfiles
            </button>
            <button
              type="button"
              onClick={run}
              disabled={!path || running}
              className="inline-flex items-center gap-1.5 rounded-md bg-accent-500 px-3.5 py-2 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Play size={13} aria-hidden="true" />
              {running ? "Checking…" : "Check dependencies"}
            </button>
          </>
        }
        secondary={
          <>
            {running && (
              <InlineState
                tone="running"
                compact
                title="Checking dependencies"
                description={result ? "Previous completed results remain available below." : undefined}
                progress={
                  <ProgressBar
                    indeterminate={!progress?.total}
                    value={progress?.done ?? 0}
                    max={progress?.total ?? 0}
                    label={progressLabel}
                  />
                }
              />
            )}
            {preview && preview.length > 0 && !running && (
              <div className="flex flex-wrap gap-2" aria-label="Detected lockfiles">
                {preview.map((lockfile) => (
                  <span
                    key={lockfile.path}
                    className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-900 px-2.5 py-1 font-mono text-[11px] text-stone-400"
                  >
                    <Boxes size={11} aria-hidden="true" className="text-sky-400" />
                    {lockfile.path.split(/[\\/]/).pop()}
                    <span className="text-stone-600">({lockfile.packages} pkgs)</span>
                  </span>
                ))}
              </div>
            )}
            {error && result && !running && <DependencyError detail={error} onRetry={run} />}
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
        <section
          aria-label="Dependency scan summary"
          className="grid grid-cols-2 overflow-hidden rounded-lg border border-ink-700 bg-ink-850 min-[700px]:grid-cols-5"
        >
          <SummaryMetric label="Lockfiles" value={result.summary.lockfilesFound.length.toLocaleString()} />
          <SummaryMetric label="Packages found" value={result.summary.packagesFound.toLocaleString()} />
          <SummaryMetric label="Packages checked" value={result.summary.packagesQueried.toLocaleString()} />
          <SummaryMetric label="Vulnerabilities" value={vulns.length.toLocaleString()} />
          <SummaryMetric label="Critical / High" value={`${critical} / ${high}`} />
        </section>
      )}

      {result && vulns.length > 0 && (
        <section aria-label="Dependency vulnerabilities" className="overflow-hidden rounded-lg border border-ink-700 bg-ink-850">
          <ResultsToolbar
            countLabel={`${filteredVulns.length} of ${vulns.length} vulnerabilities`}
            search={
              <label className="relative min-w-0">
                <span className="sr-only">Search dependency vulnerabilities</span>
                <Search
                  size={13}
                  aria-hidden="true"
                  className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-stone-500"
                />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search package or advisory…"
                  className="w-52 rounded-md border border-ink-600 bg-ink-900 py-1.5 pl-8 pr-2 text-[12px] text-stone-200 placeholder:text-stone-600"
                />
              </label>
            }
          />
          {filteredVulns.length > 0 ? (
            <SplitWorkspace
              listLabel="Vulnerable packages"
              detailLabel="Advisory detail"
              hasSelection={hasExplicitSelection}
              onBackToList={() => setSelectedKey(null)}
              list={<VulnerabilityTable vulnerabilities={filteredVulns} selected={selected} onSelect={setSelectedKey} />}
              detail={selected ? <AdvisoryDetail vulnerability={selected} onOpenReference={openUrl} /> : <InlineState tone="empty" compact title="Select an advisory" />}
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
                  className="rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:bg-ink-700"
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

      {!result && error && !running && <DependencyError detail={error} onRetry={run} />}

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
    <div className="max-h-[39rem] overflow-y-auto">
      <div className="grid grid-cols-[minmax(7rem,1.5fr)_minmax(4rem,.8fr)_minmax(4rem,.8fr)_minmax(4rem,.8fr)_auto] gap-2 border-b border-ink-700 bg-ink-900/45 px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.1em] text-stone-500">
        <span>Package</span>
        <span>Installed</span>
        <span>Fixed</span>
        <span>Ecosystem</span>
        <span>Risk</span>
      </div>
      <div className="divide-y divide-ink-800">
        {vulnerabilities.map((vulnerability) => {
          const current = selected !== null && vulnerabilityKey(selected) === vulnerabilityKey(vulnerability);
          return (
            <button
              key={vulnerabilityKey(vulnerability)}
              type="button"
              aria-current={current}
              onClick={() => onSelect(vulnerabilityKey(vulnerability))}
              className={`grid w-full grid-cols-[minmax(7rem,1.5fr)_minmax(4rem,.8fr)_minmax(4rem,.8fr)_minmax(4rem,.8fr)_auto] items-center gap-2 border-l-2 px-3 py-2.5 text-left text-[11px] transition-colors ${
                current ? "border-accent-500 bg-accent-500/5" : "border-transparent hover:bg-ink-800"
              }`}
            >
              <span className="min-w-0">
                <span className="block truncate font-mono font-medium text-stone-200">{vulnerability.packageName}</span>
                <span className="mt-0.5 block truncate text-stone-500">{vulnerability.id}</span>
              </span>
              <span className="truncate font-mono text-stone-400" title={vulnerability.installedVersion}>
                {vulnerability.installedVersion}
              </span>
              <span className="truncate font-mono text-stone-400" title={vulnerability.fixedVersions.join(", ")}>
                {vulnerability.fixedVersions[0] ?? "—"}
              </span>
              <span className="truncate text-stone-400" title={vulnerability.ecosystem}>
                {vulnerability.ecosystem}
              </span>
              <SeverityBadge severity={vulnerability.severity} showLabel={false} />
            </button>
          );
        })}
      </div>
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
          <p className="font-mono text-[12px] text-sky-300">{vulnerability.id}</p>
          <h2 className="mt-1 break-words text-[16px] font-semibold text-stone-100">{vulnerability.packageName}</h2>
          <p className="mt-1 text-[12px] text-stone-400">{vulnerability.summary || "No advisory summary provided."}</p>
        </div>
        <SeverityBadge severity={vulnerability.severity} />
      </div>

      <section className="mt-5 space-y-4 text-[12px]">
        <DetailSection label="Details">
          <p className="whitespace-pre-wrap leading-relaxed text-stone-300">{vulnerability.details || vulnerability.summary || "No additional details provided."}</p>
        </DetailSection>
        <div className="grid gap-4 min-[540px]:grid-cols-2">
          <DetailSection label="Installed version">
            <p className="font-mono text-stone-200">{vulnerability.installedVersion}</p>
          </DetailSection>
          <DetailSection label="Ecosystem">
            <p className="text-stone-200">{vulnerability.ecosystem}</p>
          </DetailSection>
          <DetailSection label="CVSS">
            <p className="font-mono text-stone-200">{vulnerability.cvssScore === null ? "Not published" : vulnerability.cvssScore.toFixed(1)}</p>
          </DetailSection>
          <DetailSection label="Published">
            <p className="text-stone-200">{vulnerability.published ? fmtDate(vulnerability.published) : "Not published"}</p>
          </DetailSection>
          <DetailSection label="Affected range">
            <p className="font-mono text-stone-200">{vulnerability.affectedRange ?? "Not published"}</p>
          </DetailSection>
          <DetailSection label="Lockfile">
            <p className="break-all font-mono text-stone-200">{vulnerability.lockfile || "Not reported"}</p>
          </DetailSection>
        </div>
        <DetailSection label="Advisory aliases">
          {vulnerability.aliases.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {vulnerability.aliases.map((alias) => (
                <span key={alias} className="rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-sky-300">
                  {alias}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-stone-500">No aliases reported.</p>
          )}
        </DetailSection>
        <DetailSection label="Fixed versions">
          {vulnerability.fixedVersions.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {vulnerability.fixedVersions.map((version) => (
                <span key={version} className="rounded border border-emerald-900/70 bg-emerald-950/25 px-1.5 py-0.5 font-mono text-[11px] text-emerald-300">
                  {version}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-amber-300">No fixed version published yet.</p>
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
                  className="inline-flex max-w-full items-center gap-1 rounded border border-ink-600 bg-ink-800 px-2 py-1 text-[11px] text-sky-300 hover:border-sky-500/50"
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
      <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-stone-500">{label}</h3>
      {children}
    </div>
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

function DependencyError({ detail, onRetry }: { detail: string; onRetry: () => void }): JSX.Element {
  return (
    <InlineState
      tone="error"
      compact
      title="Dependency checking failed"
      action={
        <>
          <button
            type="button"
            onClick={onRetry}
            className="rounded-md border border-red-900/80 bg-red-950/40 px-2.5 py-1.5 text-[12px] font-medium text-red-200 hover:bg-red-950/70"
          >
            Retry
          </button>
          <details className="text-[11px] text-stone-400">
            <summary className="cursor-pointer hover:text-stone-200">Technical details</summary>
            <pre className="selectable mt-2 max-h-28 max-w-full overflow-auto whitespace-pre-wrap rounded border border-ink-700 bg-ink-950 p-2 font-mono text-[11px] text-stone-400">
              {detail}
            </pre>
          </details>
        </>
      }
    />
  );
}
