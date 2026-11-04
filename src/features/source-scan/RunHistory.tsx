import { CheckCircle2, CircleDashed, LoaderCircle } from "lucide-react";
import { useState, type JSX } from "react";
import type { ScanRunSummary } from "../../lib/types";
import { fmtDateTime } from "../../lib/format";

export function RunHistory(props: {
  runs: ScanRunSummary[];
  selectedRunId: string | null;
  loadingRunId: string | null;
  running: boolean;
  onSelect(runId: string): void;
}): JSX.Element {
  const { runs, selectedRunId, loadingRunId, running, onSelect } = props;
  const projectId = runs[0]?.projectId ?? null;
  const [expansion, setExpansion] = useState({ projectId, expanded: false });
  const expanded = expansion.projectId === projectId && expansion.expanded;
  if (expansion.projectId !== projectId) setExpansion({ projectId, expanded: false });
  let visibleRuns = expanded ? runs : runs.slice(0, 3);
  const selected = runs.find(run => run.runId === selectedRunId);
  if (!expanded && selected && !visibleRuns.includes(selected)) {
    visibleRuns = [...runs.slice(0, 2), selected];
  }

  return (
    <section aria-labelledby="run-history-title" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2.5">
        <h2 id="run-history-title" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Run history
        </h2>
        {runs.length > 3 && <button type="button" aria-expanded={expanded} aria-controls="source-run-history-rows"
          className="rounded-sm px-2 py-1.5 text-[11px] text-text-secondary hover:bg-surface-hover hover:text-text-primary"
          onClick={() => setExpansion({ projectId, expanded: !expanded })}>
          {expanded ? "Show fewer runs" : `Show all ${runs.length} runs`}
        </button>}
      </div>
      {runs.length === 0 ? (
        <p className="px-3 py-4 text-[12px] text-text-muted">No previous source scans.</p>
      ) : (
        <div id="source-run-history-rows" className="divide-y divide-border">
          {visibleRuns.map((run) => {
            const selected = selectedRunId === run.runId;
            const loading = loadingRunId === run.runId;
            const completed = run.status === "completed";
            const Icon = loading ? LoaderCircle : completed ? CheckCircle2 : CircleDashed;
            return (
              <button
                key={run.runId}
                type="button"
                aria-current={selected ? "true" : undefined}
                onClick={() => onSelect(run.runId)}
                disabled={loading || running}
                className={`flex w-full items-start gap-2.5 px-3 py-2.5 text-left transition-colors ${selected ? "bg-accent-subtle" : "hover:bg-surface-hover"}`}
              >
                <Icon
                  size={14}
                  aria-hidden="true"
                  className={`mt-0.5 shrink-0 ${loading ? "animate-spin text-accent" : completed ? "text-success" : "text-warning"}`}
                />
                <span className="min-w-0 flex-1">
                  <span className="flex items-center justify-between gap-3">
                    <span className="text-[12px] font-medium text-text-primary">{fmtDateTime(run.completedAt ?? run.startedAt)}</span>
                    <span className="font-mono text-[10px] uppercase tracking-wide text-text-muted">
                      {completed ? `${run.totalFindings} findings` : "Incomplete"}
                    </span>
                  </span>
                  {completed ? (
                    <span className="mt-1 block text-[11px] text-text-muted">
                      {run.newFindings} new · {run.resolvedFindings} resolved
                    </span>
                  ) : (
                    <span className="mt-1 block text-[11px] text-text-muted">Not used as a comparison baseline</span>
                  )}
                </span>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
