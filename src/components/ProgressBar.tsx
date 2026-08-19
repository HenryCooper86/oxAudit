import { useId } from "react";

export function ProgressBar({
  value,
  max,
  label,
  indeterminate,
}: {
  value?: number;
  max?: number;
  label?: string;
  indeterminate?: boolean;
}) {
  const pct = max && value !== undefined && max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  const labelId = useId();
  const progressLabel = label ?? (indeterminate ? "Working…" : "Progress");
  return (
    <div className="w-full">
      <div className="mb-1 flex items-center justify-between text-xs text-text-muted">
        <span id={labelId} aria-live="polite">{progressLabel}</span>
        {!indeterminate && max !== undefined && value !== undefined && (
          <span aria-hidden="true" className="tabular-nums">
            {value.toLocaleString()} / {max.toLocaleString()} ({pct}%)
          </span>
        )}
      </div>
      <div
        role="progressbar"
        aria-labelledby={labelId}
        aria-valuemin={0}
        aria-valuemax={max && max > 0 ? max : 100}
        aria-valuenow={indeterminate ? undefined : value ?? 0}
        className="h-2 w-full overflow-hidden rounded-full bg-surface-active"
      >
        {indeterminate ? (
          <div className="h-full w-1/3 animate-[vc-slide_1.2s_ease-in-out_infinite] rounded-full bg-accent" />
        ) : (
          <div
            className="h-full rounded-full bg-accent transition-all duration-200"
            style={{ width: `${pct}%` }}
          />
        )}
      </div>
    </div>
  );
}
