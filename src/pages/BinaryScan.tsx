import { listen } from "@tauri-apps/api/event";
import { Ban, Binary, Play, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { FolderPicker } from "../components/FolderPicker";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Select, Switch } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import {
  filterComponents,
  highestSeverity,
  SEVERITY_FILTERS,
  type SeverityFilter,
} from "../lib/binaryScan";
import type { BinaryScanResult, BinaryToolStatus } from "../lib/types";


export function BinaryScanPage(): JSX.Element {
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const activeProject = useAppStore((state) => state.activeProject);
  const push = useToastStore((state) => state.push);

  const [toolStatus, setToolStatus] = useState<BinaryToolStatus | null>(null);
  const [checkingTool, setCheckingTool] = useState(true);
  const [path, setPath] = useState(activeProject ?? "");
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [offline, setOffline] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<string>("");
  const [result, setResult] = useState<BinaryScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const mountedRef = useRef(true);

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
        setToolStatus({
          available: false,
          program: null,
          version: null,
          source: null,
          message: `Could not check whether cve-bin-tool is installed: ${String(cause)}`,
        });
      }
    } finally {
      if (mountedRef.current) setCheckingTool(false);
    }
  }, []);

  useEffect(() => {
    void checkTool();
  }, [checkTool]);

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
    if (!running) return;
    setPageStatus("binary-scan", {
      label: "Scanning binaries",
      tone: "running",
      detail: progress || undefined,
    });
  }, [running, progress, setPageStatus]);

  const run = async () => {
    if (!path.trim() || running) return;
    setRunning(true);
    setError(null);
    setResult(null);
    setProgress("");
    setPageStatus("binary-scan", { label: "Scanning binaries", tone: "running" });

    try {
      const scan = await api.scanBinaries({
        path,
        severity: severity === "all" ? null : severity,
        offline,
      });
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

  if (checkingTool && !toolStatus) {
    return (
      <ToolPage title="Binary Scan" description="Detect vulnerable components inside compiled binaries, firmware images, and archives.">
        <InlineState tone="running" title="Looking for cve-bin-tool" />
      </ToolPage>
    );
  }

  if (!toolStatus?.available) {
    return (
      <ToolPage
        title="Binary Scan"
        description="Detect vulnerable components inside compiled binaries, firmware images, and archives."
      >
        <InlineState
          tone="unavailable"
          title="cve-bin-tool is not available"
          description={
            toolStatus?.message ??
            "oxAudit runs a copy of cve-bin-tool that you install, rather than bundling it."
          }
          action={
            <Button type="button" onClick={() => void checkTool()} variant="outline" size="md">
              <RefreshCw size={13} aria-hidden="true" />
              Check again
            </Button>
          }
        />
        <section className="rounded-sm border border-border bg-surface-secondary p-4">
          <h2 className="text-[13px] font-semibold text-text-primary">Installing it</h2>
          <p className="mt-1 text-[12px] leading-relaxed text-text-muted">
            cve-bin-tool is a separate GPL-3.0 program from the OpenSSF. oxAudit invokes it
            rather than bundling it, so it stays under its own licence and you control which
            copy runs.
          </p>
          <pre className="selectable mt-3 rounded-sm border border-border bg-surface-primary px-3 py-2 font-mono text-[12px] text-text-secondary">
            pipx install cve-bin-tool
          </pre>
          <p className="mt-2 text-[12px] leading-relaxed text-text-muted">
            If it is not on your PATH, set an explicit path in Settings. The first scan
            downloads a CVE database and can take several minutes.
          </p>
        </section>
      </ToolPage>
    );
  }

  return (
    <ToolPage
      title="Binary Scan"
      description="Detect vulnerable components inside compiled binaries, firmware images, and archives."
      context={
        <span className="font-mono text-[11px] text-text-muted">
          {toolStatus.program}
          {toolStatus.version ? ` · v${toolStatus.version}` : ""}
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
          </div>
        }
      >
        <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Target file or folder
        </label>
        <FolderPicker
          value={path}
          onChange={setPath}
          disabled={running}
          allowFiles
          placeholder="Choose a binary, firmware image, archive, or folder…"
          inputLabel="Binary scan target"
        />
      </TargetBar>

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
                        title={`${vulnerability.source}${vulnerability.score !== null ? ` · CVSS ${vulnerability.score}` : ""}`}
                        className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-primary px-2 py-1"
                      >
                        <SeverityBadge severity={vulnerability.severity} showLabel={false} />
                        <span className="font-mono text-[11px] text-text-secondary">
                          {vulnerability.cveId}
                        </span>
                        {vulnerability.score !== null && (
                          <span className="font-mono text-[10px] tabular-nums text-text-muted">
                            {vulnerability.score.toFixed(1)}
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
    </ToolPage>
  );
}
