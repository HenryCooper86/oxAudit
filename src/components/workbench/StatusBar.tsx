import type { JSX } from "react";
import { useAppStore } from "../../lib/stores";

const STATUS_MARKER = {
  neutral: "bg-stone-500",
  running: "bg-accent-400",
  success: "bg-emerald-500",
  error: "bg-red-500",
} as const;

export function StatusBar(): JSX.Element {
  const page = useAppStore((state) => state.page);
  const status = useAppStore((state) => state.pageStatus[page]);
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
    <footer className="flex h-7 items-center gap-4 border-t border-ink-800 bg-ink-900 px-3 text-[11px] text-stone-400">
      <div role="status" className="flex min-w-0 flex-1 items-center gap-1.5">
        <span className="sr-only">{status?.tone ?? "neutral"} status:</span>
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 shrink-0 rounded-full ${STATUS_MARKER[status?.tone ?? "neutral"]}`}
        />
        <span className="truncate text-stone-400">{status?.label ?? "Ready"}</span>
        {status?.detail && <span className="truncate text-stone-400">{status.detail}</span>}
      </div>
      <span className="shrink-0">
        AI {aiStatusLabel}
      </span>
      <span className="shrink-0">oxAudit v0.1.0</span>
    </footer>
  );
}
