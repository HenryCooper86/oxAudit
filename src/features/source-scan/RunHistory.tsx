import { CheckCircle2, CircleDashed, LoaderCircle } from "lucide-react";
import type { JSX } from "react";
import type { ScanRunSummary } from "../../lib/types";
import { fmtDateTime } from "../../lib/format";

export function RunHistory(props: {
  runs: ScanRunSummary[];
  selectedRunId: string | null;
  loadingRunId: string | null;
  onSelect(runId: string): void;
}): JSX.Element {
  const { runs, selectedRunId, loadingRunId, onSelect } = props;

  return (
    <section aria-labelledby="run-history-title" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
      <div className="border-b border-border px-3 py-2.5">
        <h2 id="run-history-title" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Run history
        </h2>
      </div>
      {runs.length === 0 ? (
        <p className="px-3 py-4 text-[12px] text-text-muted">No previous source scans.</p>
      ) : (
        <div className="max-h-56 overflow-y-auto divide-y divide-border">
          {runs.map((run) => {
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
                disabled={loading}
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
