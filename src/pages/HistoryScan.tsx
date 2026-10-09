import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { Ban, Clipboard, History, Play } from "lucide-react";
import { FolderPicker } from "../components/FolderPicker";
import { SeverityBadge } from "../components/SeverityBadge";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { ResultPagination } from "../components/workbench/ResultPagination";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { Button, Select, Switch } from "../components/ui";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import type { CanonicalRun, Finding, HistoryScanResult, Severity } from "../lib/types";
import { acquireScan, cancelActiveScan, detachScan, refreshScanWork, releaseScan, scanOperationId, useScanWorkStore } from "../features/project-home/coordinator";
import { readSavedScanReceipt } from "../features/runs/savedScanReceipt";
import { EvidenceSummary, historyEvidence } from "../features/runs/EvidenceSummary";
import { usePagination } from "../lib/pagination";
import { normalizeCommandError } from "../lib/commandError";

const SEVERITIES: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityOrder(finding: Finding): number {
  return SEVERITY_RANK[finding.severity] ?? Number.MAX_SAFE_INTEGER;
}

export function HistoryScanPage(): JSX.Element {
  const activeProject = useAppStore((state) => state.activeProject);
  const selectedProject = useAppStore((state) => state.selectedProject);
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const push = useToastStore((state) => state.push);
  const openExport = useAppStore(state => state.openExport);
  const activeWork = useScanWorkStore(state => state.active);
  const recoveryRevision = useScanWorkStore(state => state.recoveryRevision);

  const [path, setPath] = useState(() => useScanWorkStore.getState().lastTargets.history ?? activeProject ?? selectedProject ?? "");
  const [localRunning, setRunning] = useState(false);
  const running = localRunning || activeWork?.owner === "history";
  const [result, setResult] = useState<HistoryScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [search, setSearch] = useState("");
  const [selectedFingerprint, setSelectedFingerprint] = useState<string | null>(null);
  const [validate, setValidate] = useState(false);
  const mounted = useRef(true);
  const invocation = useRef<number | null>(null);
  const receiptRequest = useRef(0);
  const pathEdited = useRef(false);
  const [attempt, setAttempt] = useState<CanonicalRun | null>(null);
  const [receipt, setReceipt] = useState<CanonicalRun | null>(null);
  const [operationState, setOperationState] = useState<string | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      receiptRequest.current += 1;
      if (invocation.current !== null) detachScan(invocation.current);
      clearPageStatus("history-scan");
    };
  }, [clearPageStatus]);

  useEffect(() => {
    const generation = ++receiptRequest.current;
    if (activeWork?.owner === "history" && !path.trim()) { setPath(activeWork.path); return; }
    if (running || (!path.trim() && pathEdited.current)) return;
    const recent = useScanWorkStore.getState().backend.recent.find(work => work.kind === "history" && work.target === path.trim());
    void readSavedScanReceipt<HistoryScanResult>("history", path.trim(), recent?.runId).then(saved => {
      if (!mounted.current || generation !== receiptRequest.current) return;
      setAttempt(saved.attempt);
      if (saved.loadError) setError(`Saved history evidence could not be loaded: ${saved.loadError}`);
      if (saved.data) {
        setResult(saved.data);
        setReceipt(saved.receipt);
        setOperationState(null);
        if (!path.trim()) setPath(saved.target);
        setSelectedFingerprint(current => saved.data!.findings.some(finding => finding.fingerprint === current) ? current : null);
        setPageStatus("history-scan", { label: `Saved history results · ${saved.data.findings.length} findings · ${saved.data.state ?? "state unknown"}`, tone: saved.data.state === "completed" ? "success" : "neutral" });
      }
    }).catch(cause => {
      if (mounted.current && generation === receiptRequest.current) setError(`Saved history evidence could not be loaded: ${String(cause)}`);
    });
    return () => { receiptRequest.current += 1; };
  }, [activeWork?.owner, activeWork?.path, path, recoveryRevision, running, setPageStatus]);

  const run = async () => {
    const target = path.trim();
    if (!target || running || invocation.current !== null) return;
    const ownership = acquireScan("history", target, "Scanning git history");
    if (ownership === null) return;
    invocation.current = ownership;
    receiptRequest.current += 1;
    setRunning(true);
    setError(null);
    setOperationState(null);
    setSelectedFingerprint(null);
    setPageStatus("history-scan", { label: "Scanning git history…", detail: target, tone: "running" });
    try {
      const scanned = await api.scanHistorySecrets(target, validate, scanOperationId(ownership));
      const active = useScanWorkStore.getState().active;
      if (!mounted.current || active?.id !== ownership) return;
      if (active.cancelling || active.terminalStatus === "cancelled" || scanned.state === "cancelled") {
        setError("History scan cancelled; previous saved results remain available.");
        setPageStatus("history-scan", { label: "History scan cancelled", tone: "neutral" });
        return;
      }
      setResult(scanned);
      setAttempt(null);
      setReceipt(null);
      setOperationState(scanned.state && scanned.state !== "completed" ? `Latest operation ${scanned.state}` : "Operation completed");
      setPageStatus("history-scan", {
        label: scanned.truncated || (scanned.state && scanned.state !== "completed")
          ? `History scan · partial (${scanned.blobsScanned} blobs, ${scanned.findings.length} findings)`
          : scanned.findings.length
          ? `History scan · ${scanned.findings.length} historical secret${scanned.findings.length === 1 ? "" : "s"}`
          : `History scan · no findings recorded (${scanned.blobsScanned} blobs)`,
        tone: scanned.truncated || (scanned.state && scanned.state !== "completed") ? "neutral" : scanned.findings.length ? "success" : "neutral",
      });
    } catch (failure) {
      if (!mounted.current || useScanWorkStore.getState().active?.id !== ownership) return;
      const message = normalizeCommandError(failure).message;
      setError(message);
      const cancelled = message.includes("cancelled") || useScanWorkStore.getState().active?.cancelling;
      setPageStatus("history-scan", { label: cancelled ? "History scan cancelled" : "History scan failed", tone: cancelled ? "neutral" : "error" });
    } finally {
      if (mounted.current) setRunning(false);
      invocation.current = null;
      releaseScan(ownership);
      void refreshScanWork(true);
    }
  };

  const findings = useMemo(() => result?.findings ?? [], [result]);
  const filtered = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return findings
      .filter((finding) => severity === "all" || finding.severity === severity)
      .filter((finding) => {
        if (!needle) return true;
        return [finding.ruleName, finding.ruleId, finding.filePath, finding.title]
          .join(" ")
          .toLocaleLowerCase()
          .includes(needle);
      })
      .sort((a, b) => severityOrder(a) - severityOrder(b) || a.filePath.localeCompare(b.filePath) || a.line - b.line);
  }, [findings, severity, search]);
  const selected = filtered.find((finding) => finding.fingerprint === selectedFingerprint) ?? filtered[0] ?? null;
  const pagination = usePagination(filtered, 50, selected ? filtered.indexOf(selected) : -1);
  const partial = Boolean(result?.truncated || (result?.state && result.state !== "completed"));

  const copyFinding = async (finding: Finding) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
      push("success", "Finding copied — secret material stays redacted.");
    } catch {
      push("error", "Copy failed.");
    }
  };

  return (
    <ToolPage
      title="History Scan"
      description="Was this credential ever committed — including in files deleted long ago? Reads every blob reachable from any ref; rotation, not deletion, closes a leaked credential."
      context={<span className="rounded-sm border border-border px-1.5 py-0.5 text-[11px] text-text-muted">{running ? "Running" : result?.runId ? "Receipt available" : "Ready"}</span>}
    >
      <div className="mt-4 space-y-4">
        <TargetBar
          primary={
            <>
            <Button type="button" variant="primary" onClick={() => void run()} disabled={Boolean(activeWork) || running || !path.trim()}>
              <Play size={13} aria-hidden="true" />
              {running ? "Scanning history…" : "Scan history"}
            </Button>
            {running && <Button type="button" variant="danger" disabled={activeWork?.cancelling} onClick={() => void cancelActiveScan()}><Ban size={13} aria-hidden="true" />Cancel</Button>}
            </>
          }
        >
          <FolderPicker value={path} onChange={value => { pathEdited.current = true; receiptRequest.current += 1; setPath(value); setResult(null); setReceipt(null); setAttempt(null); setOperationState(null); setSelectedFingerprint(null); setError(null); }} disabled={running} inputLabel="Repository folder" placeholder="Choose a repository…" />
        </TargetBar>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Switch checked={validate} onChange={setValidate} disabled={running} label="Validate live against providers" />
          <p className="min-w-0 flex-1 text-[12px] text-text-muted">
            Off by default: the check puts each leaked credential on the wire to its own provider — GitHub, AWS,
            GitLab, OpenAI, Anthropic, Hugging Face, npm, Stripe, Slack — to learn whether it still authenticates.
            Nothing is sent anywhere else, and only the verdict is kept.
          </p>
        </div>

        {attempt && !result && attempt.state !== "completed" && <InlineState tone="unavailable" title={`Latest saved history attempt: ${attempt.state}`} description={attempt.id} />}
        {result && <EvidenceSummary label="History" evidence={historyEvidence(result, receipt)} running={running} cancelling={activeWork?.cancelling} attempt={attempt}
          operation={error ? error.toLowerCase().includes("cancelled") ? "Latest operation cancelled" : "Latest operation failed or evidence unavailable" : operationState}
          action={result.runId ? <Button type="button" variant="outline" size="sm" onClick={() => openExport(result.runId!)}>Open Export Center</Button> : undefined}>
          <p>Target: <span className="break-all font-mono">{result.target ?? path}</span></p>
          {result.gitContext && <>
            <p>Git HEAD before: <span className="break-all font-mono">{result.gitContext.headBefore ?? "Unknown"}</span></p>
            <p>Git HEAD after: <span className="break-all font-mono">{result.gitContext.headAfter ?? "Unknown"}</span></p>
          </>}
          <p>Historical findings retain redacted Git object locations; paths do not describe the current working tree.</p>
        </EvidenceSummary>}

        {result?.validation && (() => {
          const v = result.validation;
          const noAnswer = v.checked - v.live - v.rejected;
          const notAttempted =
            v.skippedNoValidator + v.skippedUnpaired + v.skippedLimit + v.skippedNotKept;
          return (
            <InlineState
              tone={v.live > 0 ? "error" : "unavailable"}
              title={`Provider check: ${v.live} live, ${v.rejected} rejected, ${noAnswer} no answer, ${notAttempted} not attempted`}
              description="Live means the provider still accepts the credential — rotate it now. Rejected is not a licence to skip rotation: the credential may work against other surfaces or be re-enabled. Not attempted covers rules without a validator and AWS key ids with no paired secret nearby."
            />
          );
        })()}

        {running && (
          <InlineState
            tone="running"
            title="Reading git history"
            description={`Scanning ${activeWork?.path ?? path}. Every distinct blob is read through bounded, read-only plumbing. Large repositories can take up to the two-minute budget.`}
          />
        )}

        {error && (
          <InlineState
            tone="error"
            title="History scan failed"
            description={error}
            action={
              <Button type="button" variant="outline" onClick={() => void run()} disabled={running || Boolean(activeWork)}>
                Retry
              </Button>
            }
          />
        )}

        {result && partial && (
          <InlineState
            tone="unavailable"
            title="History scan stopped early"
            description="The findings below are partial — treat absence as unproven. See the evidence summary for the recorded stop reason."
          />
        )}

        {result && !partial && findings.length === 0 && !running && (
          <InlineState
            tone="empty"
            title={`No findings recorded — ${result.blobsScanned} blob${result.blobsScanned === 1 ? "" : "s"} scanned`}
            description="Check the evidence summary for the recorded history scope and limits."
          />
        )}

        {result && findings.length > 0 && (
          <section aria-label="History scan results" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
            <ResultsToolbar
              countLabel={`${filtered.length} shown · ${findings.length} historical ${findings.length === 1 ? "secret" : "secrets"}`}
              filters={
                <Select
                  aria-label="Finding severity"
                  value={severity}
                  onChange={(event) => setSeverity(event.target.value as Severity | "all")}
                  variant="compact"
                >
                  {SEVERITIES.map((item) => (
                    <option key={item} value={item}>
                      {item === "all" ? "All severities" : item}
                    </option>
                  ))}
                </Select>
              }
              search={
                <label className="relative min-w-0">
                  <span className="sr-only">Search history findings</span>
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search findings…"
                    className="w-44 rounded-sm border border-border bg-surface-primary py-1.5 px-2 text-[12px] text-text-primary placeholder:text-text-muted"
                  />
                </label>
              }
            />
            <div role="tabpanel">
              <SplitWorkspace
                panelId="history-findings"
                listLabel="Historical secrets"
                list={
                  <>
                  <ul className="max-h-[36rem] overflow-auto" aria-label="Historical secret findings">
                    {pagination.items.map((finding) => {
                      const active = selected?.fingerprint === finding.fingerprint;
                      return (
                        <li key={finding.fingerprint}>
                          <button
                            type="button"
                            aria-current={active ? "true" : undefined}
                            onClick={() => setSelectedFingerprint(finding.fingerprint)}
                            className={`block w-full border-b border-border px-3 py-2.5 text-left transition-colors ${active ? "bg-accent-subtle" : "hover:bg-surface-hover"}`}
                          >
                            <div className="flex flex-wrap items-center gap-1.5">
                              <SeverityBadge severity={finding.severity} />
                              <span className="font-mono text-[12px] text-text-secondary">{finding.ruleId}</span>
                              {finding.verified === true && (
                                <span className="inline-flex items-center rounded-sm border border-sev-critical-border bg-sev-critical-subtle px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-sev-critical">
                                  Live
                                </span>
                              )}
                              {finding.verified === false && (
                                <span className="inline-flex items-center rounded-sm border border-border bg-surface-secondary px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted">
                                  Rejected
                                </span>
                              )}
                            </div>
                            <p className="mt-1 truncate text-[12px] text-text-muted">
                              {finding.filePath}:{finding.line}
                            </p>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                  <ResultPagination pagination={pagination} label="historical findings" onPageChange={pagination.setPage} />
                  </>
                }
                detailLabel="Finding detail"
                hasSelection={selectedFingerprint !== null && selected?.fingerprint === selectedFingerprint}
                onBackToList={() => setSelectedFingerprint(null)}
                detail={
                  selected ? (
                    <div className="space-y-4 p-4 text-[13px] text-text-secondary">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={selected.severity} />
                        <span className="text-[14px] font-semibold text-text-primary">{selected.title}</span>
                        <span className="font-mono text-[12px] text-text-muted">[{selected.ruleId}]</span>
                        {selected.verified === true && (
                          <span className="rounded-sm border border-sev-critical-border bg-sev-critical-subtle px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-sev-critical">
                            Live — provider accepted it
                          </span>
                        )}
                        {selected.verified === false && (
                          <span className="rounded-sm border border-border bg-surface-secondary px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted">
                            Provider rejected it
                          </span>
                        )}
                      </div>
                      {(selected.verified === true || selected.verified === false) && (
                        <p className="text-[12px] text-text-muted">
                          {selected.verified === true
                            ? "The provider still accepts this credential. Rotate it now — deletion from history does not close it."
                            : "The provider refused this credential. Rotate it anyway: it may still work against other surfaces, or be re-enabled."}
                        </p>
                      )}
                      <div>
                        <h3 className="text-[12px] font-semibold uppercase tracking-wide text-text-muted">Historical location</h3>
                        <p className="mt-1 break-all font-mono text-[12px]">
                          {selected.filePath}:{selected.line}:{selected.column}
                        </p>
                        {result.findingBlobIds?.[selected.id] && <p className="mt-1 break-all font-mono text-[12px]">Git blob: <span>{result.findingBlobIds[selected.id]}</span></p>}
                        <p className="mt-1 text-[12px] text-text-muted">
                          The file may no longer exist; the path and position describe the object in history, not your working tree.
                        </p>
                      </div>
                      <div>
                        <h3 className="text-[12px] font-semibold uppercase tracking-wide text-text-muted">Match</h3>
                        <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all rounded-sm border border-border bg-surface-primary p-2 font-mono text-[12px]">
                          {selected.matchText}
                        </pre>
                      </div>
                      <div>
                        <h3 className="text-[12px] font-semibold uppercase tracking-wide text-text-muted">Context</h3>
                        <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all rounded-sm border border-border bg-surface-primary p-2 font-mono text-[12px]">
                          {selected.context}
                        </pre>
                      </div>
                      <p>{selected.description}</p>
                      <div>
                        <h3 className="text-[12px] font-semibold uppercase tracking-wide text-text-muted">Recommendation</h3>
                        <p className="mt-1">{selected.recommendation}</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Button type="button" variant="outline" size="md" onClick={() => void copyFinding(selected)}>
                          <Clipboard size={13} aria-hidden="true" />
                          Copy finding JSON
                        </Button>
                      </div>
                      <p className="border-t border-border pt-3 text-[12px] text-text-muted">
                        Match text and context are redacted. Saved evidence retains Git object identities and historical locations. Rotation, not deletion, closes a leaked credential.
                      </p>
                    </div>
                  ) : (
                    <InlineState tone="idle" title="Select a finding" description="Choose a historical secret to inspect its redacted evidence." />
                  )
                }
              />
            </div>
          </section>
        )}

        {!result && !running && !error && (
          <InlineState
            tone="idle"
            title="Scan git history for leaked credentials"
            description="Choose a repository and run the scan. The same secret rules, entropy floors, and redaction as a working-tree scan apply; one credential in one file is one finding, however many revisions it survived."
            action={null}
          />
        )}

        <p className="flex items-center gap-1.5 text-[12px] text-text-muted">
          <History size={13} aria-hidden="true" />
          Saved history runs can be reloaded and exported with historical Git object locations.
        </p>
      </div>
    </ToolPage>
  );
}
