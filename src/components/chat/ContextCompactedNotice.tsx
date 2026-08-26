import { ChevronDown, FileClock, RotateCcw } from "lucide-react";
import { useState, type JSX } from "react";

/**
 * Marks the seam where older conversation turns were summarized to fit the
 * context window. Collapsed it reads as a one-line divider; expanded it shows
 * the summary the model is now working from, so the user can see exactly what
 * the assistant remembers instead of guessing why it seems to have forgotten.
 *
 * When `onRetry` is provided (the most recent turn only), it offers to re-answer
 * with the full conversation uncompacted — useful after raising the context
 * window or switching to a larger-context model.
 */
export function ContextCompactedNotice({
  summarizedMessages,
  summary,
  onRetry,
}: {
  summarizedMessages: number;
  summary: string;
  onRetry?: () => void;
}): JSX.Element {
  const [open, setOpen] = useState(false);

  return (
    <section
      aria-label="Context compaction"
      className="rounded-sm border border-border bg-surface-secondary"
    >
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <FileClock size={13} aria-hidden="true" className="text-accent" />
        <span className="text-[11px] font-medium text-text-secondary">
          Earlier messages summarized to fit the context window
        </span>
        <span className="ml-auto font-mono text-[11px] tabular-nums text-text-muted">
          {summarizedMessages} turn{summarizedMessages === 1 ? "" : "s"}
        </span>
        <ChevronDown
          size={13}
          aria-hidden="true"
          className={`shrink-0 text-text-muted transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div className="border-t border-border">
          <p className="selectable px-3 py-2 text-[12px] leading-relaxed text-text-secondary">
            {summary}
          </p>
          {onRetry && (
            <div className="flex justify-end px-2 pb-2">
              <button
                type="button"
                onClick={onRetry}
                className="flex items-center gap-1.5 rounded-sm border border-border px-2 py-1 text-[11px] font-medium text-text-secondary hover:bg-surface-tertiary hover:text-text-primary"
              >
                <RotateCcw size={11} aria-hidden="true" />
                Retry with full context
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
