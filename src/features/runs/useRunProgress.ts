import { useEffect, useState } from "react";
import { listen } from "../../lib/events";
import type { ScanWorkKind } from "../../lib/types";
import { useScanWorkStore } from "../project-home/coordinator";

export const RUN_STAGE_LABELS = {
  queued: "Queued", discovering: "Discovering targets", detecting: "Detecting findings",
  normalizing: "Normalizing evidence", enriching: "Enriching evidence", assessing: "Assessing findings",
  persisting: "Saving evidence", verifying: "Verifying evidence", cancelling: "Cancelling",
  completed: "Operation completed", incomplete: "Operation incomplete", cancelled: "Operation cancelled", failed: "Operation failed",
} as const;
export type ReportedRunStage = keyof typeof RUN_STAGE_LABELS;
const TERMINAL_STATES = ["completed", "incomplete", "cancelled", "failed"];
interface ObservedProgress {
  operationId: string;
  runId: string;
  sequence: number;
  stages: ReportedRunStage[];
  current: ReportedRunStage;
}
interface RunProgressEvent {
  schemaVersion: number;
  operationId: string;
  runId: string;
  sequence: number;
  event: { kind: string; state?: string };
}

/** Lifecycle events describe this operation, never the separately saved receipt. */
export function useRunProgress(kind: ScanWorkKind) {
  const operationId = useScanWorkStore(state => state.active && state.active.owner === kind ? state.active.operationId : null);
  const [observed, setObserved] = useState<ObservedProgress | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    let disposed = false;
    let stop: (() => void) | undefined;
    void listen<RunProgressEvent>("run://event", ({ payload }) => {
      const active = useScanWorkStore.getState().active;
      if (disposed || active?.owner !== kind || !payload || payload.operationId !== active.operationId
        || payload.schemaVersion !== 1 || typeof payload.runId !== "string" || !payload.runId
        || !Number.isSafeInteger(payload.sequence) || payload.sequence < 1
        || !payload.event || typeof payload.event !== "object" || Array.isArray(payload.event)
        || typeof payload.event.kind !== "string" || !["stage_changed", "run_terminal"].includes(payload.event.kind)
        || typeof payload.event.state !== "string" || !Object.prototype.hasOwnProperty.call(RUN_STAGE_LABELS, payload.event.state)) return;
      const stage = payload.event.state as ReportedRunStage;
      if (payload.event.kind === "run_terminal" && !TERMINAL_STATES.includes(stage)) return;
      setObserved(previous => {
        const sameOperation = previous?.operationId === payload.operationId;
        if (sameOperation && (previous.runId !== payload.runId || previous.sequence >= payload.sequence || TERMINAL_STATES.includes(previous.current))) return previous;
        const stages = sameOperation ? previous.stages : [];
        return { operationId: payload.operationId, runId: payload.runId, sequence: payload.sequence,
          stages: stages.includes(stage) ? stages : [...stages, stage], current: stage };
      });
    }).then(unlisten => { if (disposed) unlisten(); else stop = unlisten; }).catch(() => { if (!disposed) setUnavailable(true); });
    return () => { disposed = true; stop?.(); };
  }, [kind]);

  return { observed: observed?.operationId === operationId ? observed : null, unavailable };
}
