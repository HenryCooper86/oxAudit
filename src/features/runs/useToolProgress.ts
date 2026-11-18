import { useCallback, useEffect, useState } from "react";
import { listen } from "../../lib/events";
import type { ScanWorkKind } from "../../lib/types";
import { useScanWorkStore } from "../project-home/coordinator";

/** A throttled progress event from a YARA or Template scan. */
export interface ToolProgress {
  operationId: string;
  message: string;
  done: number;
  total: number;
  /** YARA: bytes read so far. */
  bytesScanned?: number;
  /** Template: requests sent so far. */
  requestsSent?: number;
  /** Template: matches found so far. */
  matches?: number;
}

const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0;

/** Native events are runtime input: anything malformed, or from another operation, is ignored. */
export function parseToolProgress(payload: unknown): ToolProgress | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const row = payload as Record<string, unknown>;
  if (typeof row.operationId !== "string" || typeof row.message !== "string" || !finite(row.done) || !finite(row.total)) return null;
  return {
    operationId: row.operationId, message: row.message, done: row.done, total: row.total,
    ...(finite(row.bytesScanned) ? { bytesScanned: row.bytesScanned } : {}),
    ...(finite(row.requestsSent) ? { requestsSent: row.requestsSent } : {}),
    ...(finite(row.matches) ? { matches: row.matches } : {}),
  };
}

/** Latest progress of this page's active operation; events for any other operation are dropped. */
export function useToolProgress(owner: ScanWorkKind, event: string) {
  const [progress, setProgress] = useState<ToolProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let disposed = false;
    let stop: (() => void) | undefined;
    void listen<unknown>(event, ({ payload }) => {
      const active = useScanWorkStore.getState().active;
      if (disposed || active?.owner !== owner || active.terminalStatus) return;
      const parsed = parseToolProgress(payload);
      if (!parsed || parsed.operationId !== active.operationId) return;
      setProgress(parsed);
    }).then(unlisten => {
      if (disposed) unlisten();
      else stop = unlisten;
    }).catch(() => { if (!disposed) setError("Live progress updates are unavailable. The operation may still be running."); });
    return () => { disposed = true; stop?.(); };
  }, [owner, event]);
  const reset = useCallback(() => setProgress(null), []);
  return { progress, reset, error };
}
