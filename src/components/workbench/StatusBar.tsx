import {
  cancelActiveScan,
  useScanWorkStore,
} from "../../features/project-home/coordinator";
import { useEffect, useState, type JSX } from "react";
import { useAppStore } from "../../lib/stores";
import type { AiReadinessStatus } from "../../lib/settingsRequests";

const STATUS_MARKER = {
  neutral: "bg-text-muted opacity-60",
  running: "bg-accent animate-status-pulse",
  success: "bg-success",
  error: "bg-error",
} as const;

const AI_LABEL: Record<AiReadinessStatus, string> = {
  loading: "loading settings",
  checking: "checking",
  unconfigured: "not configured",
  offline: "offline",
  ready: "ready",
  unavailable: "status unavailable",
  unsupported: "not in this build",
};

/** oxFuzz's status dot colours: green when available, accent while working, muted otherwise. */
const AI_DOT: Record<AiReadinessStatus, string> = {
  loading: "bg-accent animate-status-pulse",
  checking: "bg-accent animate-status-pulse",
  unconfigured: "bg-text-muted opacity-60",
  offline: "bg-error",
  ready: "bg-success",
  unavailable: "bg-warning",
  unsupported: "bg-text-muted opacity-60",
};

const systemNow = () => new Date();

/** A wall clock, as in oxFuzz's status bar. Not a live region: it ticks every second. */
export function StatusClock({ now = systemNow }: { now?: () => Date }): JSX.Element {
  const [time, setTime] = useState(now);
  useEffect(() => {
    const interval = setInterval(() => setTime(now()), 1000);
    return () => clearInterval(interval);
  }, [now]);
  return (
    <time dateTime={time.toISOString()} className="shrink-0 tabular-nums">
      {time.toLocaleTimeString()}
    </time>
  );
}

export function StatusBar(): JSX.Element {
  const page = useAppStore((state) => state.page);
  const pageStatus = useAppStore((state) => state.pageStatus[page]);
  const active = useScanWorkStore((state) => state.active);
  const recoveryError = useScanWorkStore((state) => state.recoveryError);
  const status = active
    ? {
        label: active.cancelling ? "Cancelling…" : active.stage,
        detail: active.path,
        tone: "running" as const,
      }
    : pageStatus;
  const aiReadiness = useAppStore((state) => state.aiReadiness);

  return (
    <footer className="flex h-7 min-w-0 select-none items-center gap-3 border-t border-border bg-surface-secondary px-4 text-[11px] text-text-muted min-[900px]:px-6">
      <div role="status" className="flex min-w-0 flex-1 items-center gap-1.5">
        <span className="sr-only">{status?.tone ?? "neutral"} status:</span>
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 shrink-0 rounded-full ${STATUS_MARKER[status?.tone ?? "neutral"]}`}
        />
        <span className={`truncate ${status?.tone === "running" ? "text-accent" : ""}`}>{status?.label ?? "Ready"}</span>
        {status?.detail && <span className="min-w-0 truncate">{status.detail}</span>}
      </div>
      {active && (
        <button
          type="button"
          aria-label="Cancel active scan"
          disabled={active.cancelling}
          onClick={() => void cancelActiveScan()}
          className="shrink-0 rounded-sm px-1 text-error underline-offset-2 hover:underline disabled:opacity-50"
        >
          Cancel
        </button>
      )}
      {recoveryError && <span title={recoveryError} className="min-w-0 max-w-[50%] truncate text-warning">Scan status unavailable</span>}
      <span className="flex shrink-0 items-center gap-1.5 max-[600px]:sr-only">
        <span>AI {AI_LABEL[aiReadiness.status]}</span>
        <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${AI_DOT[aiReadiness.status]}`} />
      </span>
      <span aria-hidden="true" className="h-3 w-px shrink-0 bg-border max-[600px]:hidden" />
      <span className="max-[600px]:hidden">
        <StatusClock />
      </span>
    </footer>
  );
}
