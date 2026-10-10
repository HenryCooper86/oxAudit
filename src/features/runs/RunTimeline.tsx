import { LoaderCircle } from "lucide-react";
import type { ScanWorkKind } from "../../lib/types";
import { useScanWorkStore } from "../project-home/coordinator";
import { RUN_STAGE_LABELS, useRunProgress } from "./useRunProgress";

const PHASE_STAGES: Record<string, string> = {
  walking: "discovering", scanning: "detecting", parsing: "detecting",
  "querying-osv": "enriching", "loading-cache": "enriching", "matching-local": "enriching", "exploitation-signal": "enriching",
};

export interface PhaseProgress {
  operationId?: string;
  phase?: string;
  label: string;
  done?: number;
  total?: number;
  unit?: string;
  detail?: string;
}

/** Displays reported stages and phase-local counts, without an estimated overall percentage. */
export function RunTimeline({ kind, running, hasCompletedResult, progress, detail, logs, detailsOperationId, title = "Scan in progress", unavailable = false }: {
  kind: ScanWorkKind;
  running: boolean;
  hasCompletedResult: boolean;
  progress?: PhaseProgress | null;
  detail?: string;
  logs?: readonly string[];
  detailsOperationId?: string | null;
  title?: string;
  unavailable?: boolean;
}) {
  const { observed, unavailable: lifecycleUnavailable } = useRunProgress(kind);
  const cancelling = useScanWorkStore(state => Boolean(state.active && state.active.owner === kind && state.active.cancelling));
  const operationId = useScanWorkStore(state => state.active && state.active.owner === kind ? state.active.operationId : null);
  if (!running) return null;
  const current = observed?.current;
  if (progress?.operationId && progress.operationId !== operationId) progress = null;
  if (detailsOperationId && detailsOperationId !== operationId) { detail = undefined; logs = undefined; }
  if (current && progress?.phase && PHASE_STAGES[progress.phase] && PHASE_STAGES[progress.phase] !== current) progress = null;
  const validCount = progress?.unit && Number.isSafeInteger(progress.done) && Number.isSafeInteger(progress.total)
    && progress.done! >= 0 && progress.total! > 0 && progress.done! <= progress.total!;

  return (
    <section aria-label="Scan progress" className="min-w-0 rounded-sm border border-border bg-surface-secondary px-4 py-3">
      <div className="flex min-w-0 items-start gap-2">
        <LoaderCircle size={15} aria-hidden="true" className="mt-0.5 shrink-0 animate-spin text-accent" />
        <div className="min-w-0 flex-1">
          <p role="status" aria-atomic="true" className="text-[13px] font-medium text-text-primary">
            {cancelling ? "Cancellation requested — waiting for the operation to stop" : current ? RUN_STAGE_LABELS[current] : progress?.label || title}
          </p>
          {!observed && !progress && <p className="mt-1 text-[12px] text-text-muted">Waiting for reported progress. The operation is still running.</p>}
          {(unavailable || lifecycleUnavailable) && <p className="mt-1 text-[12px] text-warning">Live progress updates are unavailable. The operation may still be running.</p>}
          {progress && <div className="mt-1 flex flex-wrap gap-x-2 text-[12px] text-text-secondary">
            <span>{progress.label}</span>
            {validCount && <span>{progress.done!.toLocaleString()} of {progress.total!.toLocaleString()} {progress.unit}</span>}
            {validCount && <span className="sr-only">Count applies to this phase only.</span>}
          </div>}
          {(detail || progress?.detail) && <p className="mt-1 break-all font-mono text-[11px] leading-relaxed text-text-muted">{detail || progress?.detail}</p>}
        </div>
      </div>
      {observed && <ol aria-label="Reported scan stages" className="mt-3 flex flex-wrap gap-2">
        {observed.stages.map(stage => <li key={stage} aria-current={stage === current ? "step" : undefined}
          className={`rounded-sm border px-2 py-1 text-[11px] ${stage === current ? "border-accent-glow text-accent" : "border-border text-text-muted"}`}>{RUN_STAGE_LABELS[stage]}</li>)}
      </ol>}
      {hasCompletedResult && <p className="mt-2 text-[11px] text-text-muted">A previous result remains available. This operation has separate progress and completion.</p>}
      {logs && logs.length > 0 && <details className="mt-2">
        <summary className="w-fit cursor-pointer text-[12px] text-text-muted">Progress details</summary>
        <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-text-secondary">{logs.join("\n")}</pre>
      </details>}
    </section>
  );
}
