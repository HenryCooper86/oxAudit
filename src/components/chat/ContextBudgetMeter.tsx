import type { ContextBudgetState } from "../../lib/contextBudget";

export function ContextBudgetMeter({
  budget,
  className = "hidden sm:flex",
}: {
  budget: ContextBudgetState;
  /** Display utilities; the composer shows it by its own width. */
  className?: string;
}) {
  const tone = {
    normal: "bg-success",
    warning: "bg-warning",
    critical: "bg-error",
  }[budget.tone];
  const title = `${budget.estimatedTokens.toLocaleString()} estimated input + ${budget.reservedOutputTokens.toLocaleString()} reserved output of ${budget.contextWindow.toLocaleString()} tokens`;

  return (
    <div
      className={`shrink-0 items-center gap-1.5 ${className}`}
      title={title}
      aria-label={`Context budget ${budget.percent} percent used. ${title}.`}
    >
      <span className="font-mono text-[10px] tabular-nums text-text-muted">
        Context {budget.percent}%
      </span>
      <span
        aria-hidden="true"
        className="h-1.5 w-12 overflow-hidden rounded-full bg-surface-tertiary"
      >
        <span
          className={`block h-full rounded-full transition-[width] ${tone}`}
          style={{ width: `${budget.percent}%` }}
        />
      </span>
    </div>
  );
}
