import { useState } from "react";
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

  const statusIcon =
    record.status === "error" ? (
      <XCircle size={14} className="text-red-400" />
    ) : running ? (
      <Clock3 size={14} className="animate-pulse text-teal-400" />
    ) : (
      <CheckCircle2 size={14} className="text-emerald-400" />
    );

  return (
    <div className="overflow-hidden rounded-lg border border-ink-700 bg-ink-900/70">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <Wrench size={13} className="shrink-0 text-slate-400" />
        <span className="shrink-0 font-mono text-[11px] font-semibold text-slate-200">
          {record.name}
        </span>
        {statusIcon}
        {record.durationMs !== null && (
          <span className="shrink-0 font-mono text-[10px] tabular-nums text-slate-500">
            {fmtDuration(record.durationMs)}
          </span>
        )}
        {record.status === "error" && (
          <span className="truncate text-[10px] text-red-400/80">
            {record.resultPreview?.slice(0, 60) ?? "failed"}
          </span>
        )}
        <ChevronDown
          size={12}
          className={`ml-auto shrink-0 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div className="selectable space-y-1.5 border-t border-ink-800 px-3 py-2">
          {record.arguments && (
            <div>
              <div className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">
                Arguments
              </div>
              <pre className="max-h-32 overflow-y-auto whitespace-pre-wrap break-all rounded bg-ink-950 px-2 py-1 font-mono text-[10px] leading-relaxed text-slate-400">
                {record.arguments}
              </pre>
            </div>
          )}
          {record.resultPreview && (
            <div>
              <div className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">
                Result
              </div>
              <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap break-all rounded bg-ink-950 px-2 py-1 font-mono text-[10px] leading-relaxed text-slate-400">
                {record.resultPreview}
              </pre>
            </div>
          )}
          {running && (
            <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-teal-400" />
              running…
            </div>
          )}
        </div>
      )}
    </div>
  );
}
