import {
  cancelActiveScan,
  useScanWorkStore,
} from "../../features/project-home/coordinator";
import type { JSX } from "react";
import { version } from "../../../package.json";
import { useAppStore } from "../../lib/stores";

const STATUS_MARKER = {
  neutral: "bg-text-muted",
  running: "bg-accent",
  success: "bg-success",
  error: "bg-error",
} as const;

export function StatusBar(): JSX.Element {
  const page = useAppStore((state) => state.page);
  const pageStatus = useAppStore((state) => state.pageStatus[page]);
  const active = useScanWorkStore((state) => state.active);
  const status = active
    ? {
        label: active.cancelling ? "Cancelling…" : active.stage,
        detail: active.path,
        tone: "running" as const,
      }
    : pageStatus;
  const aiReadiness = useAppStore((state) => state.aiReadiness);
  const aiStatusLabel = {
    loading: "loading settings",
    checking: "checking",
    unconfigured: "not configured",
    offline: "offline",
    ready: "ready",
    unavailable: "status unavailable",
  }[aiReadiness.status];

  return (
    <footer className="flex h-7 items-center gap-4 border-t border-border bg-surface-secondary px-3 text-[11px] text-text-muted">
      <div role="status" className="flex min-w-0 flex-1 items-center gap-1.5">
        <span className="sr-only">{status?.tone ?? "neutral"} status:</span>
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 shrink-0 rounded-full ${STATUS_MARKER[status?.tone ?? "neutral"]}`}
        />
        <span className="truncate">{status?.label ?? "Ready"}</span>
        {status?.detail && <span className="truncate">{status.detail}</span>}
      </div>
      {active && (
        <button
          type="button"
          aria-label="Cancel active scan"
          disabled={active.cancelling}
          onClick={() => void cancelActiveScan()}
          className="text-error disabled:opacity-50"
        >
          Cancel
        </button>
      )}
      <span className="shrink-0">AI {aiStatusLabel}</span>
      <span className="shrink-0">oxAudit v{version}</span>
    </footer>
  );
}
