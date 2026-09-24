import { useEffect, useMemo, useState, type JSX } from "react";
import { Clipboard, History, Play } from "lucide-react";
import { FolderPicker } from "../components/FolderPicker";
import { SeverityBadge } from "../components/SeverityBadge";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { Button, Select, Switch } from "../components/ui";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import type { Finding, HistoryScanResult, Severity } from "../lib/types";

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

  const [path, setPath] = useState(activeProject ?? selectedProject ?? "");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<HistoryScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [search, setSearch] = useState("");
  const [selectedFingerprint, setSelectedFingerprint] = useState<string | null>(null);
  const [validate, setValidate] = useState(false);

  useEffect(() => () => clearPageStatus("history-scan"), [clearPageStatus]);

  const run = async () => {
    const target = path.trim();
    if (!target || running) return;
    setRunning(true);
    setError(null);
    setResult(null);
    setSelectedFingerprint(null);
    setPageStatus("history-scan", { label: "Scanning git history…", detail: target, tone: "running" });
    try {
      const scanned = await api.scanHistorySecrets(target, validate);
      setResult(scanned);
      setSelectedFingerprint(scanned.findings[0]?.fingerprint ?? null);
      setPageStatus("history-scan", {
        label: scanned.findings.length
          ? `History scan · ${scanned.findings.length} historical secret${scanned.findings.length === 1 ? "" : "s"}`
          : `History scan · clean (${scanned.blobsScanned} blobs)`,
        tone: scanned.findings.length ? "success" : "neutral",
      });
    } catch (failure) {
      const message = failure instanceof Error ? failure.message : String(failure);
      setError(message);
      setPageStatus("history-scan", { label: "History scan failed", tone: "error" });
    } finally {
      setRunning(false);
    }
  };

  const findings = result?.findings ?? [];
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
  const selected = findings.find((finding) => finding.fingerprint === selectedFingerprint) ?? filtered[0] ?? null;

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
      context={<span className="rounded-sm border border-border px-1.5 py-0.5 text-[11px] text-text-muted">Not saved</span>}
    >
      <div className="mt-4 space-y-4">
        <TargetBar
          primary={
            <Button type="button" variant="primary" onClick={() => void run()} disabled={running || !path.trim()}>
              <Play size={13} aria-hidden="true" />
              {running ? "Scanning history…" : "Scan history"}
            </Button>
          }
        >
          <FolderPicker value={path} onChange={setPath} disabled={running} inputLabel="Repository folder" placeholder="Choose a repository…" />
        </TargetBar>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Switch checked={validate} onChange={setValidate} disabled={running} label="Validate live against providers" />
          <p className="min-w-0 flex-1 text-[12px] text-text-muted">
            Off by default: the check puts each leaked credential on the wire to its own provider — GitHub tokens to
            api.github.com, a paired AWS key to sts.amazonaws.com — to learn whether it still authenticates. Nothing is
            sent anywhere else, and only the verdict is kept.
          </p>
        </div>

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
            description="Every distinct blob is read through the same bounded, read-only plumbing as the review panel. Large repositories can take up to the two-minute budget."
          />
        )}

        {error && (
          <InlineState
            tone="error"
            title="History scan failed"
            description={error}
            action={
              <Button type="button" variant="outline" onClick={() => void run()} disabled={running}>
                Retry
              </Button>
            }
          />
        )}

        {result && result.truncated && (
          <InlineState
            tone="unavailable"
            title="History scan stopped early"
            description={`${result.limitNote ?? "A budget was reached"}. The findings below are partial — treat absence as unproven.`}
          />
        )}

        {result && findings.length === 0 && !running && (
          <InlineState
            tone="empty"
            title={`No secrets in history — ${result.blobsScanned} blob${result.blobsScanned === 1 ? "" : "s"} scanned`}
            description="Coverage is ref-reachable blobs only; dangling objects are not enumerated. A clean history is not proof no credential was ever typed."
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
                  <ul className="max-h-[36rem] overflow-auto" aria-label="Historical secret findings">
                    {filtered.map((finding) => {
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
                }
                detailLabel="Finding detail"
                hasSelection={selected !== null}
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
                        Match text and context are redacted. This finding is not a stored run: nothing was written to the
                        project history database, and leaving this page discards the result. Rotation, not deletion,
                        closes a leaked credential.
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
          History runs are not saved as canonical runs and export no standards formats; the CLI keeps a record when you need one.
        </p>
      </div>
    </ToolPage>
  );
}
