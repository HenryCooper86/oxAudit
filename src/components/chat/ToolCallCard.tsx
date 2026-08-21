import { useId, useState } from "react";
import { Check, ChevronRight, Clock3, Wrench, X } from "lucide-react";
import type { ToolRecord } from "../../lib/types";
import { fmtDuration } from "../../lib/format";

/**
 * A tool call card: icon + name + live status + duration, expandable to show
 * the arguments and a preview of the result. Updates in place by toolCallId.
 * Modeled on y-gui's ToolCallCard / DefaultRenderer.
 */
export function ToolCallCard({
  record,
  fill = false,
}: {
  record: ToolRecord;
  fill?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const running = record.status === "running";
  const detailsId = useId();
  const statusLabel =
    record.status === "error"
      ? "Failed"
      : running
        ? "Running"
        : "Completed";

  const statusIcon =
    record.status === "error" ? (
      <X size={12} aria-hidden="true" className="text-error" />
    ) : running ? (
      <Clock3 size={12} aria-hidden="true" className="animate-pulse text-accent" />
    ) : (
      <Check size={12} aria-hidden="true" className="text-success" />
    );

  return (
    <div className={fill ? "w-full" : "max-w-full"}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={detailsId}
        onClick={() => setOpen(!open)}
        className={`flex max-w-full items-center gap-1.5 rounded-sm border border-border bg-surface-code px-2.5 py-1.5 text-left transition-colors hover:border-border-strong hover:bg-surface-tertiary ${fill ? "w-full" : ""}`}
      >
        <Wrench size={12} aria-hidden="true" className="shrink-0 text-text-muted" />
        <span className="min-w-0 truncate font-mono text-[12px] font-medium text-text-primary">
          {record.name}
        </span>
        {statusIcon}
        <span aria-live="polite" className="shrink-0 text-[10px] text-text-muted">
          {statusLabel}
        </span>
        {record.durationMs !== null && (
          <span className="shrink-0 font-mono text-[11px] tabular-nums text-text-muted">
            {fmtDuration(record.durationMs)}
          </span>
        )}
        {record.status === "error" && (
          <span className="truncate text-[11px] text-error">
            {record.resultPreview?.slice(0, 60) ?? "failed"}
          </span>
        )}
        <ChevronRight
          size={12}
          aria-hidden="true"
          className={`ml-0.5 shrink-0 text-text-muted transition-transform ${open ? "rotate-90" : ""}`}
        />
      </button>
      {open && (
        <div id={detailsId} className="selectable mt-1 space-y-2 rounded-md bg-surface-secondary px-3 py-2.5">
          {record.arguments && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">
                Arguments
              </div>
              <pre className="max-h-32 overflow-y-auto whitespace-pre-wrap break-all rounded-sm bg-surface-code px-2.5 py-2 font-mono text-[12px] leading-relaxed text-text-secondary">
                {record.arguments}
              </pre>
            </div>
          )}
          {record.resultPreview && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">
                Result
              </div>
              <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap break-all rounded-sm bg-surface-code px-2.5 py-2 font-mono text-[12px] leading-relaxed text-text-secondary">
                {record.resultPreview}
              </pre>
            </div>
          )}
          {running && (
            <div className="flex items-center gap-1.5 text-[11px] text-text-secondary">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
              running…
            </div>
          )}
        </div>
      )}
    </div>
  );
}
