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
  return (
    <div className="w-full">
      {label && (
        <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
          <span>{label}</span>
          {!indeterminate && max !== undefined && value !== undefined && (
            <span className="tabular-nums">
              {value.toLocaleString()} / {max.toLocaleString()} ({pct}%)
            </span>
          )}
        </div>
      )}
      <div className="h-2 w-full overflow-hidden rounded-full bg-ink-750">
        {indeterminate ? (
          <div className="h-full w-1/3 animate-[vc-slide_1.2s_ease-in-out_infinite] rounded-full bg-teal-400/80" />
        ) : (
          <div
            className="h-full rounded-full bg-gradient-to-r from-teal-500 to-emerald-400 transition-all duration-200"
            style={{ width: `${pct}%` }}
          />
        )}
      </div>
    </div>
  );
}
