import { useId, useState } from "react";
import { CheckCircle2, ChevronDown, Clock3, Wrench, XCircle } from "lucide-react";
import type { ToolRecord } from "../../lib/types";
import { fmtDuration } from "../../lib/format";

/**
 * A tool call card: icon + name + live status + duration, expandable to show
 * the arguments and a preview of the result. Updates in place by toolCallId.
 * Modeled on y-gui's ToolCallCard / DefaultRenderer.
 */
export function ToolCallCard({ record }: { record: ToolRecord }) {
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
      <XCircle size={14} aria-hidden="true" className="text-red-400" />
    ) : running ? (
      <Clock3 size={14} aria-hidden="true" className="animate-pulse text-accent-400" />
    ) : (
      <CheckCircle2 size={14} aria-hidden="true" className="text-emerald-400" />
    );

  return (
    <div className="overflow-hidden rounded-lg border border-ink-700 bg-ink-900/70">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={detailsId}
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <Wrench size={13} aria-hidden="true" className="shrink-0 text-stone-400" />
        <span className="shrink-0 font-mono text-[12px] font-semibold text-stone-200">
          {record.name}
        </span>
        {statusIcon}
        <span aria-live="polite" className="text-[11px] text-stone-300">
          {statusLabel}
        </span>
        {record.durationMs !== null && (
          <span className="shrink-0 font-mono text-[11px] tabular-nums text-stone-400">
            {fmtDuration(record.durationMs)}
          </span>
        )}
        {record.status === "error" && (
          <span className="truncate text-[11px] text-red-300">
            {record.resultPreview?.slice(0, 60) ?? "failed"}
          </span>
        )}
        <ChevronDown
          size={12}
          aria-hidden="true"
          className={`ml-auto shrink-0 text-stone-500 transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div id={detailsId} className="selectable space-y-1.5 border-t border-ink-800 px-3 py-2">
          {record.arguments && (
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-stone-300">
                Arguments
              </div>
              <pre className="max-h-32 overflow-y-auto whitespace-pre-wrap break-all rounded bg-ink-950 px-2 py-1 font-mono text-[13px] leading-relaxed text-stone-300">
                {record.arguments}
              </pre>
            </div>
          )}
          {record.resultPreview && (
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-stone-300">
                Result
              </div>
              <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap break-all rounded bg-ink-950 px-2 py-1 font-mono text-[13px] leading-relaxed text-stone-300">
                {record.resultPreview}
              </pre>
            </div>
          )}
          {running && (
            <div className="flex items-center gap-1.5 text-[11px] text-stone-300">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent-400" />
              running…
            </div>
          )}
        </div>
      )}
    </div>
  );
}
