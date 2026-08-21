import { listen } from "@tauri-apps/api/event";
import { Ban, Binary, Play, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { FolderPicker } from "../components/FolderPicker";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, SectionLabel, Select, Switch } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { latestCompletedRun } from "../lib/durableRuns";
import { useAppStore, useToastStore } from "../lib/stores";
import {
  filterComponents,
  highestSeverity,
  SEVERITY_FILTERS,
  type SeverityFilter,
} from "../lib/binaryScan";
import type { BinaryScannersStatus, BinaryScanResult } from "../lib/types";
import { RunTimeline } from "../features/runs/RunTimeline";


export function BinaryScanPage(): JSX.Element {
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const activeProject = useAppStore((state) => state.activeProject);
  const push = useToastStore((state) => state.push);

  const [toolStatus, setToolStatus] = useState<BinaryScannersStatus | null>(null);
  const [useGrype, setUseGrype] = useState(true);
  const [checkingTool, setCheckingTool] = useState(true);
  const [path, setPath] = useState(activeProject ?? "");
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [offline, setOffline] = useState(false);
  const [deepAnalysis, setDeepAnalysis] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<string>("");
  // Caveats that are not failures — a rate-limited or capped CVE lookup means
  // "fewer findings than exist", which looks exactly like "clean" unless said.
  const [notes, setNotes] = useState<string[]>([]);
  const [result, setResult] = useState<BinaryScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const mountedRef = useRef(true);
  const historyRequestRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearPageStatus("binary-scan");
    };
  }, [clearPageStatus]);

  const checkTool = useCallback(async () => {
    setCheckingTool(true);
    try {
      const status = await api.binaryToolStatus();
      if (mountedRef.current) setToolStatus(status);
    } catch (cause) {
      // Failing to *ask* is a different problem from the tool being absent, and
      // saying so keeps a backend fault from reading as "you forgot to install it".
      if (mountedRef.current) {
        const unavailable = {
          available: false,
          program: null,
          version: null,
          source: null,
          message: `Could not check which scanners are installed: ${String(cause)}`,
        };
        setToolStatus({
          // The native scanner is built in and cannot be absent, so a scan can
          // still run even when probing the external tools failed.
          native: {
            available: true,
            program: "oxAudit (built-in)",
            version: null,
            source: null,
            message: "Built in — no installation required.",
          },
          cveBinTool: unavailable,
          grype: unavailable,
          docker: unavailable,
          runtime: "auto",
          canScan: true,
        });
      }
    } finally {
      if (mountedRef.current) setCheckingTool(false);
    }
  }, []);

  useEffect(() => {
    void checkTool();
  }, [checkTool]);

  useEffect(() => {
    const requestedPath = path.trim();
    const requestId = ++historyRequestRef.current;
    if (!requestedPath) return;

    void (async () => {
      try {
        const runs = await api.listCanonicalRuns("binary");
        const saved = latestCompletedRun(runs, "binary", requestedPath);
        if (!saved || requestId !== historyRequestRef.current) return;
        const restored = await api.loadCanonicalProjection<BinaryScanResult>(saved.id);
        if (requestId !== historyRequestRef.current || !mountedRef.current) return;
        setResult(restored);
        setPageStatus("binary-scan", {
          label: `Saved binary results · ${restored.summary.vulnerabilities} CVEs`,
          tone: restored.summary.vulnerabilities > 0 ? "error" : "success",
        });
      } catch {
        // Saved history is best-effort and never blocks a new scan.
      }
    })();
  }, [path, setPageStatus]);

  // cve-bin-tool's own output is the only sign of life during a first run,
  // where it downloads the CVE database before scanning anything.
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listen<string>("binscan://progress", ({ payload }) => {
      if (!disposed) setProgress(String(payload));
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listen<string>("binscan://note", ({ payload }) => {
      const note = String(payload);
      // De-duplicated: one note per distinct message, however many sources
      // raised it.
      if (!disposed) setNotes((current) => (current.includes(note) ? current : [...current, note]));
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    if (!running) return;
    setPageStatus("binary-scan", {
      label: "Scanning binaries",
      tone: "running",
      detail: progress || undefined,
    });
  }, [running, progress, setPageStatus]);

  const run = async () => {
    if (!path.trim() || running) return;
    historyRequestRef.current += 1;
    setRunning(true);
    setError(null);
    setProgress("");
    setNotes([]);
    setPageStatus("binary-scan", { label: "Scanning binaries", tone: "running" });

    try {
      const scan = await api.scanBinaries(
        {
          path,
          severity: severity === "all" ? null : severity,
          offline,
          deepAnalysis,
        },
        useGrype && (toolStatus?.grype.available ?? false),
      );
      if (!mountedRef.current) return;
      setResult(scan);
      setPageStatus("binary-scan", {
        label: `${scan.summary.vulnerabilities} CVEs in ${scan.summary.components} components`,
        tone: scan.summary.vulnerabilities > 0 ? "error" : "success",
      });
    } catch (cause) {
      if (!mountedRef.current) return;
      const message = String(cause);
      setError(message);
      if (message.includes("cancelled")) {
        clearPageStatus("binary-scan");
      } else {
        setPageStatus("binary-scan", { label: "Binary scan failed", tone: "error" });
        push("error", message);
      }
    } finally {
      if (mountedRef.current) {
        setRunning(false);
        setProgress("");
      }
    }
  };

  const changePath = (nextPath: string) => {
    if (nextPath === path) return;
    historyRequestRef.current += 1;
    setPath(nextPath);
    setResult(null);
    setError(null);
    setNotes([]);
    clearPageStatus("binary-scan");
  };

  const refreshDatabase = async () => {
    if (running) return;
    setRunning(true);
    setError(null);
    setProgress("Refreshing the CVE database — this downloads roughly a gigabyte.");
    setPageStatus("binary-scan", { label: "Refreshing CVE database", tone: "running" });
    try {
      await api.refreshBinaryDatabase();
      push("success", "CVE database refreshed.");
      clearPageStatus("binary-scan");
    } catch (cause) {
      const message = String(cause);
      setError(message);
      setPageStatus("binary-scan", { label: "Database refresh failed", tone: "error" });
    } finally {
      setRunning(false);
      setProgress("");
    }
  };

  const cancel = async () => {
    try {
      await api.cancelBinaryScan();
    } catch {
      /* the scan's own rejection remains the source of truth */
    }
  };

  const components = filterComponents(result?.components ?? [], filter);

  const grypeReady = toolStatus?.grype.available ?? false;
  const cveBinToolReady =
    toolStatus?.runtime === "docker"
      ? (toolStatus?.docker.available ?? false)
      : (toolStatus?.cveBinTool.available ?? false) ||
        (toolStatus?.runtime === "auto" && (toolStatus?.docker.available ?? false));

  const activeScanners = [
    {
      name: "oxAudit",
      version: toolStatus?.native.version ?? null,
      detail: toolStatus?.native.message ?? "Built-in scanner",
    },
    cveBinToolReady && {
      name: "cve-bin-tool",
      version: toolStatus?.cveBinTool.version ?? null,
      detail:
        toolStatus?.runtime === "docker"
          ? "running in the container runtime"
          : (toolStatus?.cveBinTool.program ?? ""),
    },
    grypeReady &&
      useGrype && {
        name: "grype",
        version: toolStatus?.grype.version ?? null,
        detail: toolStatus?.grype.program ?? "",
      },
  ].filter(Boolean) as { name: string; version: string | null; detail: string }[];

  if (checkingTool && !toolStatus) {
    return (
      <ToolPage title="Binary Scan" description="Detect vulnerable components inside compiled binaries, firmware images, and archives.">
        <InlineState tone="running" title="Looking for cve-bin-tool" />
      </ToolPage>
    );
  }

  // The native scanner is built in, so a scan can always run. External tools
  // add coverage rather than being a prerequisite; their install notes live in
  // an optional section at the bottom of the page rather than a blocking gate.
  const moreScanners = (
    <section className="rounded-sm border border-border bg-surface-secondary p-4">
      <h2 className="text-[13px] font-semibold text-text-primary">
        Optional: add external scanners
      </h2>
      <p className="mt-1 text-[12px] leading-relaxed text-text-muted">
        oxAudit&rsquo;s built-in scanner needs nothing installed and runs on every scan.
        These two see different things and can run alongside it — grype reads package
        metadata and reports fix versions; cve-bin-tool&rsquo;s ~450 checkers find
        components statically linked into stripped binaries.
      </p>
      <dl className="mt-3 space-y-3">
        <div>
          <dt className="text-[12px] font-medium text-text-primary">
            grype{toolStatus?.grype.available ? " — installed" : " — Apache-2.0, one static binary"}
          </dt>
          {!toolStatus?.grype.available && (
            <dd>
              <pre className="selectable mt-1 rounded-sm border border-border bg-surface-primary px-3 py-2 font-mono text-[12px] text-text-secondary">
                brew install grype
              </pre>
            </dd>
          )}
        </div>
        <div>
          <dt className="text-[12px] font-medium text-text-primary">
            cve-bin-tool{toolStatus?.cveBinTool.available ? " — installed" : " — GPL-3.0, needs Python"}
          </dt>
          {!toolStatus?.cveBinTool.available && (
            <dd>
              <pre className="selectable mt-1 rounded-sm border border-border bg-surface-primary px-3 py-2 font-mono text-[12px] text-text-secondary">
                pipx install cve-bin-tool
              </pre>
              <p className="mt-1 text-[11px] leading-relaxed text-text-muted">
                Its CVE bootstrap is broken upstream; the Docker runtime carries the fix.
                Choose it in Settings, and build the image with{" "}
                <code className="font-mono">docker build -t oxaudit/cve-bin-tool:3.4 docker/cve-bin-tool</code>.
              </p>
            </dd>
          )}
        </div>
      </dl>
    </section>
  );

  return (
    <ToolPage
      title="Binary Scan"
      description="Detect vulnerable components inside compiled binaries, firmware images, and archives."
      context={
        <span className="flex flex-wrap items-center gap-1.5">
          {activeScanners.map((scanner) => (
            <span
              key={scanner.name}
              title={scanner.detail}
              className="inline-flex items-center gap-1 rounded-full border border-accent-glow bg-accent-subtle px-2 py-0.5 font-mono text-[10px] text-accent"
            >
              {scanner.name}
              {scanner.version ? ` ${scanner.version}` : ""}
            </span>
          ))}
        </span>
      }
    >
      <TargetBar
        primary={
          running ? (
            <Button type="button" onClick={() => void cancel()} variant="danger" size="md">
              <Ban size={13} aria-hidden="true" />
              Cancel
            </Button>
          ) : (
            <Button
              type="button"
              onClick={() => void run()}
              disabled={!path.trim()}
              variant="primary"
              size="md"
            >
              <Play size={13} aria-hidden="true" />
              Run scan
            </Button>
          )
        }
        secondary={
          <div className="flex flex-wrap items-center gap-4">
            <label className="flex items-center gap-2 text-[12px] text-text-secondary">
              Minimum severity
              <Select
                variant="compact"
                value={severity}
                onChange={(event) => setSeverity(event.target.value as SeverityFilter)}
                disabled={running}
              >
                {SEVERITY_FILTERS.map((level) => (
                  <option key={level} value={level}>
                    {level === "all" ? "All severities" : level}
                  </option>
                ))}
              </Select>
            </label>
            <Switch
              checked={offline}
              onChange={setOffline}
              disabled={running}
              label="Offline (use the downloaded database only)"
            />
            <Switch
              checked={deepAnalysis}
              onChange={setDeepAnalysis}
              disabled={running}
              label="Deep object calls (single file, bounded)"
            />
            <Switch
              checked={useGrype && grypeReady}
              onChange={setUseGrype}
              disabled={running || !grypeReady}
              label={
                grypeReady
                  ? "Also run grype"
                  : "Also run grype (not installed)"
              }
            />
          </div>
        }
      >
        <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Target file or folder
        </label>
        <FolderPicker
          value={path}
          onChange={changePath}
          disabled={running}
          allowFiles
          placeholder="Choose a binary, firmware image, archive, or folder…"
          inputLabel="Binary scan target"
        />
      </TargetBar>

      <RunTimeline
        active={!running && result ? "completed" : !running ? "discovering" : progress.toLowerCase().includes("enrich") ? "enriching" : "detecting"}
        running={running}
        hasCompletedResult={Boolean(result)}
      />

      {running && (
        <InlineState
          tone="running"
          title="cve-bin-tool is running"
          description={
            progress ||
            "Starting up. A first run downloads the CVE database before scanning, which can take several minutes."
          }
        />
      )}

      {notes.length > 0 && !running && (
        <div className="rounded-sm border border-warning-subtle bg-warning-subtle px-4 py-3">
          <SectionLabel>Caveats</SectionLabel>
          <ul className="mt-2 space-y-1">
            {notes.map((note) => (
              <li key={note} className="text-sm text-text-secondary">
                {note}
              </li>
            ))}
          </ul>
        </div>
      )}

      {error && !running && !error.includes("cancelled") && (
        <InlineState
          tone="error"
          title="Binary scan failed"
          description={error}
          action={
            // Offered only when the message is the stale-cache case, which is
            // the one failure a refresh actually resolves.
            error.includes("Refresh CVE database") ? (
              <Button
                type="button"
                onClick={() => void refreshDatabase()}
                variant="outline"
                size="md"
              >
                <RefreshCw size={13} aria-hidden="true" />
                Refresh CVE database
              </Button>
            ) : undefined
          }
        />
      )}

      {result && !running && (
        <section className="rounded-sm border border-border bg-surface-secondary">
          <ResultsToolbar
            countLabel={`${result.summary.components} components · ${result.summary.vulnerabilities} CVEs`}
            filters={
              <Select
                variant="compact"
                aria-label="Minimum severity shown"
                value={filter}
                onChange={(event) => setFilter(event.target.value as SeverityFilter)}
              >
                {SEVERITY_FILTERS.map((level) => (
                  <option key={level} value={level}>
                    {level === "all" ? "All severities" : `${level} and above`}
                  </option>
                ))}
              </Select>
            }
            actions={
              <span className="font-mono text-[11px] tabular-nums text-text-muted">
                {result.scanners.length > 0 ? `${result.scanners.join(" + ")} · ` : ""}
                {(result.durationMs / 1000).toFixed(1)}s
                {result.databaseLastUpdated ? ` · db ${result.databaseLastUpdated}` : ""}
              </span>
            }
          />

          {components.length === 0 ? (
            <InlineState
              tone="empty"
              compact
              title={
                result.summary.components === 0
                  ? "No known-vulnerable components found"
                  : "No components match this filter"
              }
              description={
                result.summary.components === 0
                  ? `Scanned ${result.target}. cve-bin-tool recognized no components with known CVEs.`
                  : undefined
              }
            />
          ) : (
            <ul className="divide-y divide-border">
              {components.map((component) => (
                <li key={`${component.vendor}:${component.product}:${component.version}`} className="px-3 py-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Binary size={13} aria-hidden="true" className="shrink-0 text-text-muted" />
                    <span className="font-mono text-[13px] font-semibold text-text-primary">
                      {component.product}
                    </span>
                    <span className="font-mono text-[12px] text-text-secondary">
                      {component.version}
                    </span>
                    <span className="text-[11px] text-text-muted">{component.vendor}</span>
                    <span className="ml-auto flex items-center gap-2">
                      {component.detectedBy.length > 0 && (
                        <span className="hidden font-mono text-[10px] text-text-muted sm:inline">
                          {component.detectedBy.join(" + ")}
                        </span>
                      )}
                      <SeverityBadge severity={highestSeverity(component)} />
                      <span className="font-mono text-[11px] tabular-nums text-text-muted">
                        {component.vulnerabilities.length} CVE
                        {component.vulnerabilities.length === 1 ? "" : "s"}
                      </span>
                    </span>
                  </div>

                  {component.paths.length > 0 && (
                    <p className="selectable mt-1 truncate font-mono text-[11px] text-text-muted">
                      {component.paths.join(" · ")}
                    </p>
                  )}

                  <ul className="mt-2 flex flex-wrap gap-1.5">
                    {component.vulnerabilities.map((vulnerability) => (
                      <li
                        key={vulnerability.cveId}
                        title={`${vulnerability.source}${vulnerability.score !== null ? ` · CVSS ${vulnerability.score}` : ""}${vulnerability.epssProbability !== null ? ` · EPSS ${(vulnerability.epssProbability * 100).toFixed(1)}%` : ""}`}
                        className={`inline-flex items-center gap-1.5 rounded-sm border px-2 py-1 ${
                          vulnerability.knownExploited
                            ? "border-sev-critical-border bg-sev-critical-subtle"
                            : "border-border bg-surface-primary"
                        }`}
                      >
                        <SeverityBadge severity={vulnerability.severity} showLabel={false} />
                        <span className="font-mono text-[11px] text-text-secondary">
                          {vulnerability.cveId}
                        </span>
                        {vulnerability.knownExploited && (
                          <span
                            title={
                              vulnerability.ransomware
                                ? "In CISA KEV — used in ransomware campaigns"
                                : "In CISA's Known Exploited Vulnerabilities catalog"
                            }
                            className="inline-flex items-center gap-0.5 rounded-full bg-sev-critical px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-wide text-white"
                          >
                            {vulnerability.ransomware ? "KEV · ransomware" : "KEV"}
                          </span>
                        )}
                        {vulnerability.score !== null && (
                          <span className="font-mono text-[10px] tabular-nums text-text-muted">
                            {vulnerability.score.toFixed(1)}
                          </span>
                        )}
                        {vulnerability.fixedIn && (
                          <span
                            title={`Fixed in ${vulnerability.fixedIn}`}
                            className="font-mono text-[10px] text-success"
                          >
                            →{vulnerability.fixedIn}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {result?.semanticAnalysis && !running && (
        <section className="rounded-sm border border-border bg-surface-secondary p-4">
          <h2 className="text-[13px] font-semibold text-text-primary">Deep object-call analysis</h2>
          <p className="mt-1 font-mono text-[11px] text-text-muted">
            {result.semanticAnalysis.architecture} · {result.semanticAnalysis.functionsAnalyzed.toLocaleString()} functions · {result.semanticAnalysis.callEdges.toLocaleString()} relocation call edges · {result.semanticAnalysis.unresolvedEdges.toLocaleString()} unresolved
          </p>
          <p className="mt-2 text-[11px] leading-relaxed text-text-muted">{result.semanticAnalysis.limitations.join(" ")}</p>
          {result.semanticAnalysis.findings.length === 0 ? (
            <InlineState tone="empty" compact title="No bounded dangerous-sink calls were found" description="This does not prove their absence in stripped or statically resolved code." />
          ) : (
            <ul className="mt-3 divide-y divide-border rounded-sm border border-border bg-surface-primary">
              {result.semanticAnalysis.findings.map((finding) => (
                <li key={`${finding.ruleId}:${finding.functionAddress}`} className="px-3 py-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-[12px] text-text-primary">{finding.ruleId}</span>
                    <span className="font-mono text-[10px] text-text-muted">0x{finding.functionAddress.toString(16)} · {(finding.confidence * 100).toFixed(0)}% evidence confidence</span>
                  </div>
                  <p className="mt-1 text-[11px] text-text-muted">{finding.limitations.join(" ")}</p>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {moreScanners}
    </ToolPage>
  );
}
